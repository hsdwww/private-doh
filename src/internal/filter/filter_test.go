package filter

import (
	"testing"
)

func mk(t *testing.T, blocks []string, allows []string) *List {
	t.Helper()
	l, err := NewList(blocks, allows, "hash1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestWildcardMatchesRootAndSubdomains(t *testing.T) {
	l := mk(t, []string{"*.example.com"}, nil)
	for _, q := range []string{"example.com", "www.example.com", "a.b.example.com"} {
		if ok, _ := l.Blocked(q); !ok {
			t.Errorf("%s should be blocked", q)
		}
	}
}

func TestNoFalseSuffixHit(t *testing.T) {
	l := mk(t, []string{"*.example.com"}, nil)
	if ok, _ := l.Blocked("notexample.com"); ok {
		t.Fatal("notexample.com must not be blocked")
	}
	if ok, _ := l.Blocked("example.com.evil.net"); ok {
		t.Fatal("suffix-in-middle must not be blocked")
	}
}

func TestCaseAndTrailingDot(t *testing.T) {
	l := mk(t, []string{"*.Example.COM"}, nil)
	if ok, _ := l.Blocked("WWW.example.com."); !ok {
		t.Fatal("case/dot normalization failed")
	}
}

func TestRejectBadSyntax(t *testing.T) {
	for _, bad := range []string{
		"||ads.example^", "example.com", "@@||x^", "*.example.com/path",
		"*.com", "0.0.0.0 example.com", "https://ads.example.com",
	} {
		if _, err := NewList([]string{bad}, nil, "h", "v"); err == nil {
			t.Errorf("expected reject: %s", bad)
		}
	}
}

func TestAllowlistExactAndWildcard(t *testing.T) {
	l := mk(t, []string{"*.example.com", "*.ads.example.net"}, []string{"api.example.com", "*.ok.example.net"})
	cases := []struct {
		q    string
		want bool
	}{
		{"api.example.com", false},
		{"www.example.com", true},
		{"x.ok.example.net", false},
		{"ads.example.net", true},
	}
	for _, c := range cases {
		if ok, _ := l.Blocked(c.q); ok != c.want {
			t.Errorf("%s: got %v want %v", c.q, ok, c.want)
		}
	}
}

func TestCommentsAndBlanks(t *testing.T) {
	l, err := NewList([]string{"# Title: test", "", "*.ad.example.org", "# comment"}, nil, "h", "v")
	if err != nil {
		t.Fatal(err)
	}
	if l.Count() != 1 {
		t.Fatalf("count=%d", l.Count())
	}
}

func TestParentWalkDeepSubdomain(t *testing.T) {
	l := mk(t, []string{"*.x.example.io"}, nil)
	if ok, rule := l.Blocked("deep.sub.x.example.io"); !ok || rule != "*.x.example.io" {
		t.Fatalf("deep walk failed: %v %s", ok, rule)
	}
}
