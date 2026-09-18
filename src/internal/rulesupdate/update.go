// Package rulesupdate: transactional HaGeZi rule updates with rollback.
package rulesupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"private-doh/internal/filter"
)

// UpdateConfig controls the update transaction.
type UpdateConfig struct {
	SourceURL  string `json:"source_url"`
	RulesDir   string `json:"rules_dir"`
	MinEntries int   `json:"min_entries"`
	MaxEntries int   `json:"max_entries"`
	MaxDeltaPct int  `json:"max_delta_pct"`
	Protected  []string `json:"protected_domains"`
}

// LoadUpdateConfig reads the updater JSON config.
func LoadUpdateConfig(path string) (*UpdateConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c UpdateConfig
	if err := jsonUnmarshalStrict(raw, &c); err != nil {
		return nil, err
	}
	if c.SourceURL == "" || c.RulesDir == "" {
		return nil, fmt.Errorf("source_url and rules_dir required")
	}
	if c.MinEntries == 0 {
		c.MinEntries = 10000
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 200000
	}
	if c.MaxDeltaPct == 0 {
		c.MaxDeltaPct = 30
	}
	return &c, nil
}

// Summary describes a successful update.
type Summary struct {
	SHA     string
	Version string
	Count   int
	When    time.Time
}

// httpFetch is swappable for tests.
var httpFetch = func(url string, timeout time.Duration) ([]byte, string, error) {
	client := &http.Client{Timeout: timeout, Transport: noProxyTransport()}
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		return nil, "304", nil
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	lm := resp.Header.Get("Last-Modified")
	return body, lm, nil
}

// Run performs one transactional update.
func Run(cfg *UpdateConfig) (*Summary, error) {
	if err := acquireLock(cfg.RulesDir); err != nil {
		return nil, err
	}
	defer releaseLock(cfg.RulesDir)

	body, lm, err := httpFetch(cfg.SourceURL, 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if lm == "304" {
		cur, err := readMeta(cfg.RulesDir, "current")
		if err == nil {
			return &Summary{SHA: cur.SHA, Version: cur.Version, Count: cur.Count, When: time.Now()}, nil
		}
		return nil, fmt.Errorf("304 without local version")
	}
	sum, err := validateAndPublish(cfg, body, lm)
	if err != nil {
		return nil, err
	}
	return sum, nil
}

// validateAndPublish: syntax check -> sanity gates -> atomic dir swap.
func validateAndPublish(cfg *UpdateConfig, body []byte, lm string) (*Summary, error) {
	lines := strings.Split(string(body), "\n")
	version := extractHeader(lines, "Version")
	if version == "" {
		version = time.Now().UTC().Format("20060102.1504")
	}

	// parse into filter.List (validates every wildcard line)
	norm := normalizeLines(lines)
	fl, err := filter.NewList(norm, nil, "", version)
	if err != nil {
		return nil, fmt.Errorf("syntax: %w", err)
	}
	count := fl.Count()
	if count < cfg.MinEntries || count > cfg.MaxEntries {
		return nil, fmt.Errorf("entry count %d outside [%d,%d]", count, cfg.MinEntries, cfg.MaxEntries)
	}

	// delta gate vs current
	if cur, err := readMeta(cfg.RulesDir, "current"); err == nil && cur.Count > 0 {
		delta := abs(count-cur.Count) * 100 / cur.Count
		if delta > cfg.MaxDeltaPct {
			return nil, fmt.Errorf("count changed %d%% (>%d%%) - manual review required", delta, cfg.MaxDeltaPct)
		}
	}

	// protected domains must not be blocked
	for _, p := range cfg.Protected {
		if ok, _ := fl.Blocked(p); ok {
			return nil, fmt.Errorf("protected domain %s would be blocked", p)
		}
	}

	sha := sha256.Sum256(body)
	shaHex := hex.EncodeToString(sha[:])

	// publish into versions/<sha>/ then swap current symlink
	verDir := filepath.Join(cfg.RulesDir, "versions", shaHex)
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		return nil, err
	}
	rulesPath := filepath.Join(verDir, "light.txt")
	if err := atomicWrite(rulesPath, body); err != nil {
		return nil, err
	}
	meta := Summary{SHA: shaHex, Version: version, Count: count, When: time.Now()}
	if err := writeMeta(verDir, &meta, lm); err != nil {
		return nil, err
	}
	// current -> versions/<sha>, previous -> old current
	if err := rotateSymlinks(cfg.RulesDir, shaHex); err != nil {
		return nil, err
	}
	// keep only the newest N versions (current/previous always protected);
	// prune failures are warn-only — the update already succeeded.
	if deleted, err := PruneVersions(cfg.RulesDir, keepVersions); err == nil && len(deleted) > 0 {
		fmt.Printf("pruned old rule versions: %v\n", deleted)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: rule version prune failed (update still ok): %v\n", err)
	}
	return &meta, nil
}

// keepVersions is how many rule version directories survive each update.
const keepVersions = 2

// PruneVersions deletes the oldest version directories beyond keepN.
// Directories referenced by the current/previous symlinks are always protected.
// Missing versions dir is tolerated (empty result). Individual RemoveAll
// failures are logged and skipped — the function returns what it did delete.
func PruneVersions(rulesDir string, keepN int) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(rulesDir, "versions"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// protected set from symlink targets (bare dir names)
	protected := map[string]bool{}
	for _, link := range []string{"current", "previous"} {
		if tgt, err := os.Readlink(filepath.Join(rulesDir, link)); err == nil {
			protected[filepath.Base(tgt)] = true
		}
	}
	type cand struct {
		name    string
		modTime time.Time
	}
	var dirs []cand
	for _, e := range entries {
		if !e.IsDir() || protected[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		dirs = append(dirs, cand{e.Name(), info.ModTime()})
	}
	// keep the newest (keepN - len(protected)) unprotected dirs; delete the rest
	quota := keepN - len(protected)
	if quota < 0 {
		quota = 0
	}
	sort.Slice(dirs, func(i, j int) bool {
		if !dirs[i].modTime.Equal(dirs[j].modTime) {
			return dirs[i].modTime.After(dirs[j].modTime)
		}
		return dirs[i].name < dirs[j].name // deterministic tie-break
	})
	if len(dirs) <= quota {
		return nil, nil
	}
	var deleted []string
	for _, d := range dirs[quota:] {
		if err := os.RemoveAll(filepath.Join(rulesDir, "versions", d.name)); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to remove old rule version %s: %v\n", d.name, err)
			continue
		}
		deleted = append(deleted, d.name)
	}
	return deleted, nil
}

// LoadCurrent loads the current snapshot for the gateway, with allowlist.
// It falls back to `previous` not only when the current symlink is missing,
// but also when its target is unreadable or the rules fail to parse.
func LoadCurrent(rulesDir, allowlistPath string) (*filter.List, error) {
	allow, allowErr := filter.LoadAllowlist(allowlistPath)
	if allowErr != nil {
		return nil, allowErr
	}
	fl, curErr := loadListFrom(rulesDir, "current", allow)
	if curErr == nil {
		return fl, nil
	}
	flPrev, prevErr := loadListFrom(rulesDir, "previous", allow)
	if prevErr == nil {
		return flPrev, nil
	}
	return nil, fmt.Errorf("no usable rules snapshot (current: %v; previous: %v)", curErr, prevErr)
}

// LoadCurrentForReload is the hot-reload path: same full snapshot as startup
// (rules + allowlist). It exists so tests can assert reload never drops the
// allowlist, unlike the old LoadCurrentOnly.
func LoadCurrentForReload(rulesDir, allowlistPath string) (*filter.List, error) {
	return LoadCurrent(rulesDir, allowlistPath)
}

// loadListFrom reads and parses light.txt from the named symlink
// (current/previous). Any failure — readlink, file read, or parse — is an
// error so the caller can try the other symlink.
func loadListFrom(rulesDir, link string, allow []string) (*filter.List, error) {
	target, err := os.Readlink(filepath.Join(rulesDir, link))
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(rulesDir, target)
	if !strings.HasPrefix(target, "versions/") {
		dir = target
	}
	body, err := os.ReadFile(filepath.Join(dir, "light.txt"))
	if err != nil {
		return nil, err
	}
	meta, _ := readMetaByDir(dir)
	return filter.NewList(strings.Split(string(body), "\n"), allow, meta.SHA, meta.Version)
}

// ReloadState tracks content fingerprints so the watcher only swaps the
// in-memory filter when rules OR allowlist actually changed.
type ReloadState struct {
	rulesDir   string
	allowPath  string
	lastFp     string
	loadedOnce bool
}

// NewReloadState builds a reload tracker for one watcher loop.
func NewReloadState(rulesDir, allowlistPath string) *ReloadState {
	return &ReloadState{rulesDir: rulesDir, allowPath: allowlistPath}
}

// fingerprint hashes the current symlink target plus the allowlist body,
// so allowlist-only edits are detected (file is tiny; content hash, not mtime).
func (s *ReloadState) fingerprint() string {
	h := sha256.New()
	if target, err := os.Readlink(filepath.Join(s.rulesDir, "current")); err == nil {
		h.Write([]byte(target))
	}
	h.Write([]byte{0})
	if body, err := os.ReadFile(s.allowPath); err == nil {
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Step performs the initial load (no fingerprint skip).
func (s *ReloadState) Step() (*filter.List, error) {
	l, err := LoadCurrentForReload(s.rulesDir, s.allowPath)
	if err != nil {
		return nil, err
	}
	s.lastFp = s.fingerprint()
	s.loadedOnce = true
	return l, nil
}

// StepIfChanged reloads only when the fingerprint changed since the last
// successful load. On failure it returns (nil, false, err) and keeps the old
// fingerprint so the next step retries.
func (s *ReloadState) StepIfChanged() (*filter.List, bool, error) {
	if !s.loadedOnce {
		l, err := s.Step()
		if err != nil {
			return nil, false, err
		}
		return l, true, nil
	}
	fp := s.fingerprint()
	if fp == s.lastFp {
		return nil, false, nil
	}
	l, err := LoadCurrentForReload(s.rulesDir, s.allowPath)
	if err != nil {
		return nil, false, err // keep old fingerprint: retry next cycle
	}
	s.lastFp = fp
	return l, true, nil
}

// WatchAndReload polls rules+allowlist fingerprints and invokes cb on change.
// The reload always loads the FULL snapshot (rules + allowlist); failures keep
// the old in-memory filter and are retried on the next cycle.
func WatchAndReload(rulesDir, allowlistPath string, cb func(*filter.List)) {
	st := NewReloadState(rulesDir, allowlistPath)
	for {
		time.Sleep(60 * time.Second)
		l, changed, err := st.StepIfChanged()
		if err != nil || !changed {
			continue // keep old snapshot on failure; retry next cycle
		}
		cb(l)
	}
}

// LoadCurrentOnly loads rules without allowlist.
// DEPRECATED: kept only for backward compatibility of external callers;
// the hot-reload path must use LoadCurrentForReload (allowlist included).
func LoadCurrentOnly(rulesDir string) (*filter.List, error) {
	return LoadCurrent(rulesDir, "")
}

// ---------- helpers ----------

func normalizeLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func extractHeader(lines []string, key string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, "# "+key+": ") {
			return strings.TrimSpace(strings.TrimPrefix(l, "# "+key+": "))
		}
	}
	return ""
}

func abs(x int) int { if x < 0 { return -x }; return x }

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeMeta(dir string, meta *Summary, lm string) error {
	m := map[string]string{
		"sha256": meta.SHA, "version": meta.Version,
		"count": strconv.Itoa(meta.Count), "last_modified": lm,
		"fetched_at": meta.When.UTC().Format(time.RFC3339),
	}
	var sb strings.Builder
	for k, v := range m {
		sb.WriteString(k + "=" + v + "\n")
	}
	return atomicWrite(filepath.Join(dir, "meta.txt"), []byte(sb.String()))
}

func readMeta(rulesDir, link string) (*Summary, error) {
	target, err := os.Readlink(filepath.Join(rulesDir, link))
	if err != nil {
		return nil, err
	}
	return readMetaByDir(filepath.Join(rulesDir, target))
}

func readMetaByDir(dir string) (*Summary, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "meta.txt"))
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if i := strings.Index(l, "="); i > 0 {
			m[l[:i]] = l[i+1:]
		}
	}
	c, _ := strconv.Atoi(m["count"])
	return &Summary{SHA: m["sha256"], Version: m["version"], Count: c}, nil
}

func rotateSymlinks(rulesDir, newSHA string) error {
	curPath := filepath.Join(rulesDir, "current")
	old, err := os.Readlink(curPath)
	if err != nil && !os.IsNotExist(err) {
		// current exists but is not a symlink (corrupted state) — refuse to
		// silently replace it; previous would stay stale and the real target
		// of the corrupted entry could end up unprotected (prunable).
		return fmt.Errorf("read current symlink: %w", err)
	}
	newLink := filepath.Join("versions", newSHA)

	// Guard: republishing the SAME sha must not collapse previous onto current
	// (would destroy the rollback slot and skew the prune protected set).
	if old == newLink {
		return nil // already current; keep previous as the real previous
	}

	// Order matters: establish `previous` FIRST, then flip `current`. If we
	// flipped current first and the previous-rename failed silently (the old
	// bug), prune could later delete the just-demoted rollback version.
	if old != "" {
		prevTmp := filepath.Join(rulesDir, "previous.tmp")
		os.Remove(prevTmp) // idempotent: clear stale leftovers from crashed runs
		if err := os.Symlink(old, prevTmp); err != nil {
			return fmt.Errorf("stage previous symlink: %w", err)
		}
		if err := os.Rename(prevTmp, filepath.Join(rulesDir, "previous")); err != nil {
			os.Remove(prevTmp)
			return fmt.Errorf("rotate previous symlink: %w", err)
		}
	}

	tmp := curPath + ".tmp"
	os.Remove(tmp) // idempotent: a stale current.tmp from a crashed run must not wedge every future update
	if err := os.Symlink(newLink, tmp); err != nil {
		return fmt.Errorf("stage current symlink: %w", err)
	}
	if err := os.Rename(tmp, curPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rotate current symlink: %w", err)
	}
	return nil
}

// process-wide update lock
var lockMu sync.Mutex
var lockFile *os.File

func acquireLock(rulesDir string) error {
	lockMu.Lock()
	os.MkdirAll(rulesDir, 0o755)
	f, err := os.OpenFile(filepath.Join(rulesDir, ".update.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		lockMu.Unlock()
		return err
	}
	if err := tryFlock(f); err != nil {
		f.Close()
		lockMu.Unlock()
		return fmt.Errorf("another update is running")
	}
	lockFile = f
	return nil
}

func releaseLock(rulesDir string) {
	if lockFile != nil {
		unFlock(lockFile)
		lockFile.Close()
		lockFile = nil
	}
	lockMu.Unlock()
}
