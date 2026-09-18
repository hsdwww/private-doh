// Package filter parses HaGeZi wildcard rules and answers block lookups.
// Matching contract: *.example.com blocks example.com itself and all subdomains.
package filter

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// List is an immutable snapshot of rules + allowlist.
type List struct {
	blocked   map[string]struct{}
	allowed   map[string]struct{} // exact allow entries
	allowedWC []string            // wildcard allow (*.domain)
	rulesHash string
	count     int
	version   string
}

// NewList builds a snapshot from raw lines of the block file and allowlist file.
func NewList(blockLines, allowLines []string, rulesHash, version string) (*List, error) {
	l := &List{
		blocked: map[string]struct{}{},
		allowed: map[string]struct{}{},
	}
	bad := []string{}
	for _, raw := range blockLines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d, ok := parseWildcard(line)
		if !ok {
			bad = append(bad, line)
			continue
		}
		l.blocked[d] = struct{}{}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("invalid rule syntax: %s (and %d more)", bad[0], len(bad)-1)
	}
	l.count = len(l.blocked)
	l.rulesHash = rulesHash
	l.version = version
	for _, raw := range allowLines {
		line := strings.TrimSpace(strings.ToLower(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			d, ok := parseWildcard(line)
			if !ok {
				return nil, fmt.Errorf("invalid allowlist entry: %s", line)
			}
			l.allowedWC = append(l.allowedWC, d)
		} else {
			if !validDomain(line) {
				return nil, fmt.Errorf("invalid allowlist entry: %s", line)
			}
			l.allowed[line] = struct{}{}
		}
	}
	return l, nil
}

// parseWildcard accepts "*.domain" and returns lowercase domain.
func parseWildcard(line string) (string, bool) {
	if !strings.HasPrefix(line, "*.") {
		return "", false
	}
	d := strings.ToLower(strings.TrimSuffix(line[2:], "."))
	if !validDomain(d) {
		return "", false
	}
	return d, true
}

// validDomain is a conservative ASCII hostname check.
func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false // reject single-label like "com" / "localhost"
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
	}
	return true
}

// Blocked reports whether qname (no trailing dot, lowercase) is blocked,
// after applying the allowlist. It checks qname and all its parents.
func (l *List) Blocked(qname string) (bool, string) {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	if _, ok := l.allowed[q]; ok {
		return false, ""
	}
	for _, w := range l.allowedWC {
		if q == w || strings.HasSuffix(q, "."+w) {
			return false, ""
		}
	}
	// walk qname and parents: a.b.c -> match rule stored for any level
	parts := strings.Split(q, ".")
	for i := range parts {
		cand := strings.Join(parts[i:], ".")
		if _, ok := l.blocked[cand]; ok {
			return true, "*." + cand
		}
	}
	return false, ""
}

// Count returns the number of unique blocked domains.
func (l *List) Count() int { return l.count }

// Hash returns the source file hash.
func (l *List) Hash() string { return l.rulesHash }

// Version returns the source version header.
func (l *List) Version() string { return l.version }

// LoadAllowlist reads allowlist lines from a file (missing file = empty).
func LoadAllowlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
