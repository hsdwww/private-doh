package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `{
  "listen_addr": "0.0.0.0:8443",
  "token": "0123456789abcdef0123456789abcdef01234567",
  "tls_dir": "/var/lib/private-doh-tls",
  "rules_dir": "/var/lib/private-doh-rules",
  "allowlist_path": "/etc/private-doh/allowlist.txt",
  "block_https_rr": true,
  "filter_enabled": true,
  "max_cache_entries": 5000,
  "upstreams": [
    {"name":"google","url":"https://dns.google/dns-query","dial_ips":["8.8.8.8","8.8.4.4"],"timeout_ms":2000},
    {"name":"quad9","url":"https://dns12.quad9.net/dns-query","dial_ips":["9.9.9.12","149.112.112.12"],"timeout_ms":2500}
  ]
}`

func TestLoadRejectsUnknownField(t *testing.T) {
	p := writeTemp(t, `{"listen_addr":"x","token":"`+token32()+`","unexpected":1}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func token32() string { return "0123456789abcdef0123456789abcdef" }

func TestLoadRejectsShortToken(t *testing.T) {
	p := writeTemp(t, `{"listen_addr":"0.0.0.0:8443","token":"short"}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected short-token error")
	}
}

func TestLoadRejectsNoUpstream(t *testing.T) {
	p := writeTemp(t, `{"listen_addr":"0.0.0.0:8443","token":"`+token32()+`","upstreams":[]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected no-upstream error")
	}
}

func TestLoadDefaults(t *testing.T) {
	p := writeTemp(t, `{"listen_addr":"0.0.0.0:8443","token":"`+token32()+`",
		"tls_dir":"/a","rules_dir":"/b","max_cache_entries":0,
		"upstreams":[{"name":"g","url":"https://dns.google/dns-query","dial_ips":["8.8.8.8"],"timeout_ms":2000}]}`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxCacheEntries != 5000 {
		t.Fatalf("default entries = %d", c.MaxCacheEntries)
	}
}

func TestLoadValidFull(t *testing.T) {
	c, err := Load(writeTemp(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Upstreams) != 2 || !c.BlockHTTPSRR {
		t.Fatalf("bad parse: %+v", c)
	}
}
