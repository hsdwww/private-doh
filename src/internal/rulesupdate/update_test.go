package rulesupdate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"private-doh/internal/filter"
)

// setupRulesDir creates a rules dir with current -> versions/<sha> and an allowlist file.
func setupRulesDir(t *testing.T, rulesLines, allowLines []string) string {
	t.Helper()
	dir := t.TempDir()
	ver := filepath.Join(dir, "versions", "aaaa1111")
	if err := os.MkdirAll(ver, 0o755); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range rulesLines {
		body += l + "\n"
	}
	body += "# Version: v1\n"
	if err := os.WriteFile(filepath.Join(ver, "light.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ver, "meta.txt"), []byte("sha256=aaaa1111\nversion=v1\ncount="+itoa(len(rulesLines))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("versions/aaaa1111", filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	allow := ""
	for _, l := range allowLines {
		allow += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "allowlist.txt"), []byte(allow), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// RED 1: hot reload must keep the allowlist (old bug: LoadCurrentOnly passed "").
func TestReloadKeepsAllowlist(t *testing.T) {
	dir := setupRulesDir(t, []string{"*.ads.example.com"}, []string{"track.ads.example.com"})
	// hot-reload path must include the allowlist (old LoadCurrentOnly dropped it)
	l3, err := LoadCurrentForReload(dir, filepath.Join(dir, "allowlist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := l3.Blocked("track.ads.example.com"); blocked {
		t.Fatal("hot reload lost allowlist (old bug: LoadCurrentOnly)")
	}
	if blocked, _ := l3.Blocked("other.ads.example.com"); !blocked {
		t.Fatal("non-allowlisted subdomain must stay blocked")
	}
}

// RED 2: previous fallback when current target unreadable/broken (not just Readlink failure).
func TestLoadCurrentFallsBackToPrevious(t *testing.T) {
	dir := t.TempDir()
	// previous: good version
	ver1 := filepath.Join(dir, "versions", "bbbb2222")
	os.MkdirAll(ver1, 0o755)
	os.WriteFile(filepath.Join(ver1, "light.txt"), []byte("*.old.example.com\n"), 0o644)
	os.WriteFile(filepath.Join(ver1, "meta.txt"), []byte("sha256=bbbb2222\nversion=vold\ncount=1\n"), 0o644)
	// current: dangling symlink
	os.Symlink("versions/deadbeef", filepath.Join(dir, "current"))
	os.Symlink("versions/bbbb2222", filepath.Join(dir, "previous"))
	l, err := LoadCurrent(dir, "")
	if err != nil {
		t.Fatalf("must fall back to previous on unreadable current: %v", err)
	}
	if blocked, _ := l.Blocked("x.old.example.com"); !blocked {
		t.Fatal("previous rules not active after fallback")
	}
}

// RED 3: broken current parse + previous good -> fallback (parse failure, not readlink failure).
func TestLoadCurrentParseFailFallsBack(t *testing.T) {
	dir := t.TempDir()
	verBad := filepath.Join(dir, "versions", "bad00000")
	os.MkdirAll(verBad, 0o755)
	os.WriteFile(filepath.Join(verBad, "light.txt"), []byte("!!!not-a-wildcard!!!\n"), 0o644)
	os.WriteFile(filepath.Join(verBad, "meta.txt"), []byte("sha256=bad00000\nversion=vbad\ncount=1\n"), 0o644)
	verGood := filepath.Join(dir, "versions", "good1111")
	os.MkdirAll(verGood, 0o755)
	os.WriteFile(filepath.Join(verGood, "light.txt"), []byte("*.good.example.com\n"), 0o644)
	os.WriteFile(filepath.Join(verGood, "meta.txt"), []byte("sha256=good1111\nversion=vgood\ncount=1\n"), 0o644)
	os.Symlink("versions/bad00000", filepath.Join(dir, "current"))
	os.Symlink("versions/good1111", filepath.Join(dir, "previous"))
	l, err := LoadCurrent(dir, "")
	if err != nil {
		t.Fatalf("parse failure of current must fall back to previous: %v", err)
	}
	if blocked, _ := l.Blocked("y.good.example.com"); !blocked {
		t.Fatal("previous not active after parse-failure fallback")
	}
}

// RED 4: cold start with broken current AND no previous -> degraded error is distinguishable.
func TestLoadCurrentColdStartDegraded(t *testing.T) {
	dir := t.TempDir()
	os.Symlink("versions/deadbeef", filepath.Join(dir, "current"))
	_, err := LoadCurrent(dir, "")
	if err == nil {
		t.Fatal("both broken must error (caller keeps DNS up in degraded mode)")
	}
}

// RED 5: single-step reload helper — allowlist-only change takes effect.
func TestReloadAllowlistOnlyChange(t *testing.T) {
	dir := setupRulesDir(t, []string{"*.ads.example.com"}, []string{})
	st := NewReloadState(dir, filepath.Join(dir, "allowlist.txt"))
	l1, err := st.Step()
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := l1.Blocked("track.ads.example.com"); !blocked {
		t.Fatal("without allowlist entries domain must be blocked")
	}
	// whitelist-only edit (rules symlink unchanged)
	os.WriteFile(filepath.Join(dir, "allowlist.txt"), []byte("track.ads.example.com\n"), 0o644)
	l2, changed, err := st.StepIfChanged()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("allowlist-only change must trigger reload")
	}
	if blocked, _ := l2.Blocked("track.ads.example.com"); blocked {
		t.Fatal("allowlist-only change must take effect")
	}
}

// RED 6: content fingerprint — unchanged rules+allowlist => no reload (no cache wipe).
func TestReloadNoChangeNoReload(t *testing.T) {
	dir := setupRulesDir(t, []string{"*.ads.example.com"}, []string{"track.ads.example.com"})
	st := NewReloadState(dir, filepath.Join(dir, "allowlist.txt"))
	_, err := st.Step()
	if err != nil {
		t.Fatal(err)
	}
	_, changed, err := st.StepIfChanged()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged content must not trigger reload")
	}
}

// RED 7: new version published -> reload picks it up (with allowlist intact).
func TestReloadNewVersionKeepsAllowlist(t *testing.T) {
	dir := setupRulesDir(t, []string{"*.ads.example.com"}, []string{"track.ads.example.com"})
	st := NewReloadState(dir, filepath.Join(dir, "allowlist.txt"))
	if _, err := st.Step(); err != nil {
		t.Fatal(err)
	}
	// publish new version
	ver2 := filepath.Join(dir, "versions", "cccc3333")
	os.MkdirAll(ver2, 0o755)
	os.WriteFile(filepath.Join(ver2, "light.txt"), []byte("*.ads.example.com\n*.new.example.com\n# Version: v2\n"), 0o644)
	os.WriteFile(filepath.Join(ver2, "meta.txt"), []byte("sha256=cccc3333\nversion=v2\ncount=2\n"), 0o644)
	os.Remove(filepath.Join(dir, "current"))
	os.Symlink("versions/cccc3333", filepath.Join(dir, "current"))
	l2, changed, err := st.StepIfChanged()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("new version must trigger reload")
	}
	if blocked, _ := l2.Blocked("z.new.example.com"); !blocked {
		t.Fatal("new rules not active")
	}
	if blocked, _ := l2.Blocked("track.ads.example.com"); blocked {
		t.Fatal("allowlist lost after version change (old bug)")
	}
}

// RED 8: reload failure keeps old snapshot and retries next step.
func TestReloadFailureKeepsOldAndRetries(t *testing.T) {
	dir := setupRulesDir(t, []string{"*.ads.example.com"}, []string{})
	st := NewReloadState(dir, filepath.Join(dir, "allowlist.txt"))
	l1, err := st.Step()
	if err != nil {
		t.Fatal(err)
	}
	// break current (dangling) and remove previous
	os.Remove(filepath.Join(dir, "current"))
	os.Symlink("versions/doesnotexist", filepath.Join(dir, "current"))
	l2, changed, err := st.StepIfChanged()
	if err == nil || changed || l2 != nil {
		t.Fatal("broken state must fail without replacing snapshot")
	}
	if blocked, _ := l1.Blocked("x.ads.example.com"); !blocked {
		t.Fatal("old snapshot must remain usable")
	}
	// repair by PUBLISHING A NEW VERSION (pointing back at the same old version
	// would be a no-change fingerprint, which correctly skips reload)
	ver2 := filepath.Join(dir, "versions", "dddd4444")
	os.MkdirAll(ver2, 0o755)
	os.WriteFile(filepath.Join(ver2, "light.txt"), []byte("*.ads.example.com\n# Version: v2\n"), 0o644)
	os.WriteFile(filepath.Join(ver2, "meta.txt"), []byte("sha256=dddd4444\nversion=v2\ncount=1\n"), 0o644)
	os.Remove(filepath.Join(dir, "current"))
	os.Symlink("versions/dddd4444", filepath.Join(dir, "current"))
	l3, changed2, err := st.StepIfChanged()
	if err != nil || !changed2 {
		t.Fatalf("repaired state must reload: err=%v changed=%v", err, changed2)
	}
	if blocked, _ := l3.Blocked("x.ads.example.com"); !blocked {
		t.Fatal("reloaded snapshot must work")
	}
}

var _ = filter.NewList

// ---- PruneVersions: keep exactly N versions, protected (current/previous) first ----

func mkVer(t *testing.T, dir, sha string, age time.Duration) {
	t.Helper()
	ver := filepath.Join(dir, "versions", sha)
	os.MkdirAll(ver, 0o755)
	os.WriteFile(filepath.Join(ver, "light.txt"), []byte("*.x.example.com\n"), 0o644)
	past := time.Now().Add(-age)
	os.Chtimes(filepath.Join(ver, "light.txt"), past, past)
	os.Chtimes(ver, past, past)
}

// RED 1: 4 versions, keep 2 -> current+previous survive (even though current is
// the OLDEST), the two mid-age unreferenced ones are deleted.
func TestPruneVersionsKeepsTwo(t *testing.T) {
	dir := t.TempDir()
	mkVer(t, dir, "v1old", 100*time.Hour) // current, oldest
	mkVer(t, dir, "v2", 50*time.Hour)     // unreferenced
	mkVer(t, dir, "v3", 30*time.Hour)     // unreferenced
	mkVer(t, dir, "v4new", 10*time.Hour)  // previous
	os.Symlink("versions/v1old", filepath.Join(dir, "current"))
	os.Symlink("versions/v4new", filepath.Join(dir, "previous"))
	deleted, err := PruneVersions(dir, 2)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	got := map[string]bool{}
	for _, d := range deleted {
		got[d] = true
	}
	if len(got) != 2 || !got["v2"] || !got["v3"] {
		t.Fatalf("want delete exactly {v2,v3}, got %v", deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, "versions", "v1old")); err != nil {
		t.Fatal("current target (even though oldest) must survive")
	}
	if _, err := os.Stat(filepath.Join(dir, "versions", "v4new")); err != nil {
		t.Fatal("previous target must survive")
	}
}

// RED 2: under the limit -> no-op, no error.
func TestPruneVersionsNoopWhenUnderLimit(t *testing.T) {
	dir := t.TempDir()
	mkVer(t, dir, "only1", time.Hour)
	os.Symlink("versions/only1", filepath.Join(dir, "current"))
	deleted, err := PruneVersions(dir, 2)
	if err != nil || len(deleted) != 0 {
		t.Fatalf("under limit must no-op: deleted=%v err=%v", deleted, err)
	}
}

// RED 3: missing versions dir is tolerated (warn-only, never fails the update).
func TestPruneVersionsMissingDirTolerated(t *testing.T) {
	dir := t.TempDir()
	if _, err := PruneVersions(filepath.Join(dir, "does-not-exist"), 2); err != nil {
		t.Fatalf("missing versions dir must be tolerated: %v", err)
	}
}

// RED 4: single delete failure is contained — remaining deletes still attempted,
// function returns the successful deletions without error escalation.
// NOTE: real RemoveAll permission failures cannot be injected as root; this test
// verifies the CONTRACT (delete succeeds, result reported, no error) — the
// warn-and-continue branch is exercised only in production/journal. Kept honest
// by not claiming failure-injection coverage we don't have.
func TestPruneVersionsIndividualFailureContained(t *testing.T) {
	dir := t.TempDir()
	mkVer(t, dir, "a1", 40*time.Hour) // current
	mkVer(t, dir, "b2", 30*time.Hour) // previous
	mkVer(t, dir, "c3", 20*time.Hour) // to delete
	os.Symlink("versions/a1", filepath.Join(dir, "current"))
	os.Symlink("versions/b2", filepath.Join(dir, "previous"))
	deleted, err := PruneVersions(dir, 2)
	if err != nil {
		t.Fatalf("individual failure must not escalate: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "c3" {
		t.Fatalf("want {c3} deleted, got %v", deleted)
	}
}

// ---- rotateSymlinks regression tests (Luna-audit fixes) ----

// RED 5 (order-proving): when the CURRENT stage fails, `previous` must ALREADY
// point at the demoted old current — proving the previous-first order. A mere
// final-state check cannot distinguish order (Luna mutation finding); failing
// at the current stage and inspecting the intermediate state can.
func TestRotateSymlinksPreviousEstablishedFirst(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "current"))
	os.Symlink("versions/zzz-old", filepath.Join(dir, "previous")) // stale junk

	if err := rotateSymlinks(dir, "bbb"); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.Readlink(filepath.Join(dir, "current"))
	prev, _ := os.Readlink(filepath.Join(dir, "previous"))
	if cur != "versions/bbb" {
		t.Fatalf("current must point to new: %s", cur)
	}
	if prev != "versions/aaa" {
		t.Fatalf("previous must point at the DEMOTED old current: %s", prev)
	}
	// no leftover tmp symlinks
	if _, err := os.Lstat(filepath.Join(dir, "current.tmp")); !os.IsNotExist(err) {
		t.Fatal("current.tmp leftover")
	}
	if _, err := os.Lstat(filepath.Join(dir, "previous.tmp")); !os.IsNotExist(err) {
		t.Fatal("previous.tmp leftover")
	}
}

// RED 5b (order proof via injected current-stage failure): a stale non-empty
// current.tmp directory blocks the current symlink rename; if the order is
// correct, previous has ALREADY been rotated to the old current when the
// failure surfaces — and (post idempotent-cleanup fix) a stale symlink-shaped
// current.tmp is cleared so rotation succeeds anyway. We use a DIRECTORY
// blocker (not clearable) to force the failure path deterministically.
func TestRotateSymlinksCurrentStageFailureProvesOrder(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "current"))

	// non-empty DIRECTORY named current.tmp: os.Remove cannot clear it,
	// os.Symlink then fails with EEXIST — deterministic current-stage failure
	os.MkdirAll(filepath.Join(dir, "current.tmp", "nested"), 0o755)

	err := rotateSymlinks(dir, "bbb")
	if err == nil {
		t.Fatal("current stage must fail against directory blocker")
	}
	// ORDER PROOF: previous must already be rotated to the old current
	prev, _ := os.Readlink(filepath.Join(dir, "previous"))
	if prev != "versions/aaa" {
		t.Fatalf("previous-first order violated: previous=%s at current-stage failure", prev)
	}
	// current must NOT have moved
	cur, _ := os.Readlink(filepath.Join(dir, "current"))
	if cur != "versions/aaa" {
		t.Fatalf("current must stay on old version: %s", cur)
	}
}

// RED 5c (crash-recovery): a stale SYMLINK-shaped current.tmp (from a crashed
// run) must be cleared idempotently so the next update succeeds (Luna P2).
func TestRotateSymlinksStaleCurrentTmpRecovered(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "ccc"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "current"))
	os.Symlink("versions/ccc", filepath.Join(dir, "previous"))
	// simulate crashed run: stale symlink current.tmp left behind
	os.Symlink("versions/bbb", filepath.Join(dir, "current.tmp"))

	if err := rotateSymlinks(dir, "bbb"); err != nil {
		t.Fatalf("stale symlink current.tmp must be recovered, got: %v", err)
	}
	cur, _ := os.Readlink(filepath.Join(dir, "current"))
	prev, _ := os.Readlink(filepath.Join(dir, "previous"))
	if cur != "versions/bbb" || prev != "versions/aaa" {
		t.Fatalf("recovered rotation wrong: cur=%s prev=%s", cur, prev)
	}
}

// RED 5d (corrupted current): a regular FILE at the current path must be
// refused (error propagated), never silently replaced (Luna robustness P2).
func TestRotateSymlinksRegularFileCurrentRefused(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "previous"))
	// corrupted: regular file where current symlink should be
	os.WriteFile(filepath.Join(dir, "current"), []byte("corrupt"), 0o644)

	if err := rotateSymlinks(dir, "bbb"); err == nil {
		t.Fatal("regular-file current must be refused with an error")
	}
	cur, rerr := os.Readlink(filepath.Join(dir, "current"))
	if rerr == nil && cur != "" {
		t.Fatalf("corrupted current must not be replaced: now %s", cur)
	}
}

// RED 6: republishing the SAME sha is a no-op — previous must NOT collapse onto
// current (rollback slot preserved, prune protected set stays honest).
func TestRotateSymlinksSameSHAIsNoop(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "current"))
	os.Symlink("versions/bbb", filepath.Join(dir, "previous"))

	if err := rotateSymlinks(dir, "aaa"); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.Readlink(filepath.Join(dir, "current"))
	prev, _ := os.Readlink(filepath.Join(dir, "previous"))
	if cur != "versions/aaa" || prev != "versions/bbb" {
		t.Fatalf("same-sha republish must not touch links: cur=%s prev=%s", cur, prev)
	}
}

// RED 7: previous-rotation failure must PROPAGATE (old bug: silently swallowed,
// leaving current flipped with stale previous).
func TestRotateSymlinksPreviousFailurePropagates(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions", "aaa"), 0o755)
	os.MkdirAll(filepath.Join(dir, "versions", "bbb"), 0o755)
	os.Symlink("versions/aaa", filepath.Join(dir, "current"))
	// make previous un-renameable: a non-empty DIRECTORY at the target path
	// blocks os.Rename(prevTmp -> previous) with ENOTEMPTY.
	blocker := filepath.Join(dir, "previous")
	os.MkdirAll(filepath.Join(blocker, "nested"), 0o755)

	err := rotateSymlinks(dir, "bbb")
	if err == nil {
		t.Fatal("previous rotation failure must propagate an error")
	}
	// current must NOT have flipped (order guarantee: previous first)
	cur, _ := os.Readlink(filepath.Join(dir, "current"))
	if cur != "versions/aaa" {
		t.Fatalf("current must stay on old version when previous rotation fails: %s", cur)
	}
}

// RED 8: mtime tie — with BOTH candidates UNPROTECTED (Luna mutation finding:
// the old test had alpha protected, so the tie-breaker was never executed).
// Sorting must be deterministic: same mtime -> same victim (lexicographically
// larger name = treated as older and pruned first).
func TestPruneVersionsMtimeTieDeterministic(t *testing.T) {
	build := func() string {
		dir := t.TempDir()
		// three versions; current protects only "protected"
		mkVer(t, dir, "protected", time.Hour)
		mkVer(t, dir, "alpha", time.Hour)
		mkVer(t, dir, "beta", time.Hour)
		same := time.Now().Add(-time.Hour)
		// identical mtimes on BOTH unprotected candidates -> tie-breaker engaged
		os.Chtimes(filepath.Join(dir, "versions", "alpha"), same, same)
		os.Chtimes(filepath.Join(dir, "versions", "beta"), same, same)
		os.Symlink("versions/protected", filepath.Join(dir, "current"))
		return dir
	}
	dir1 := build()
	deleted, err := PruneVersions(dir1, 2) // quota = 2-1 = 1 -> one of alpha/beta must go
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("tie must prune exactly one, got %v", deleted)
	}
	if deleted[0] != "beta" {
		t.Fatalf("tie-breaker must pick 'beta' (lexicographically larger = older), got %v", deleted)
	}
	// deterministic across identical rebuilt layouts
	dir2 := build()
	deleted2, _ := PruneVersions(dir2, 2)
	if len(deleted2) != 1 || deleted2[0] != deleted[0] {
		t.Fatalf("tie pruning must be deterministic: %v vs %v", deleted, deleted2)
	}
	// survivor check
	if _, err := os.Stat(filepath.Join(dir1, "versions", "alpha")); err != nil {
		t.Fatal("alpha must survive as the tie winner")
	}
}
