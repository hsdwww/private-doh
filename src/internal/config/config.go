// Package config implements strict loading and validation for private-doh.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Upstream is one DoH upstream with pinned dial IPs (bootstrap independence).
type Upstream struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	DialIPs   []string `json:"dial_ips"`
	TimeoutMs int      `json:"timeout_ms"`
}

// Config is the full gateway configuration.
type Config struct {
	ListenAddr      string     `json:"listen_addr"`
	Token           string     `json:"token"`
	TLSDir          string     `json:"tls_dir"`
	RulesDir        string     `json:"rules_dir"`
	AllowlistPath   string     `json:"allowlist_path"`
	BlockHTTPSRR    bool       `json:"block_https_rr"`
	FilterEnabled   bool       `json:"filter_enabled"`
	MaxCacheEntries int        `json:"max_cache_entries"`
	Upstreams       []Upstream `json:"upstreams"`
}

// Load parses and validates the config file at path. Unknown fields are rejected.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks required fields and semantics, applying safe defaults.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr required")
	}
	if len(c.Token) < 32 {
		return fmt.Errorf("token must be >= 32 chars (128-bit)")
	}
	if c.TLSDir == "" || c.RulesDir == "" {
		return fmt.Errorf("tls_dir and rules_dir required")
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream required")
	}
	for i, u := range c.Upstreams {
		if u.URL == "" {
			return fmt.Errorf("upstream %d: url required", i)
		}
		if len(u.DialIPs) == 0 {
			return fmt.Errorf("upstream %d: dial_ips required (bootstrap independence)", i)
		}
		if u.TimeoutMs <= 0 {
			return fmt.Errorf("upstream %d: timeout_ms required", i)
		}
	}
	if c.MaxCacheEntries <= 0 {
		c.MaxCacheEntries = 5000
	}
	return nil
}
