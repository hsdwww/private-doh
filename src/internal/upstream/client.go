// Package upstream provides direct, proxy-immune DoH clients with pinned dial IPs.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to one DoH upstream. It never uses environment proxies and
// dials only the pinned IPs while keeping SNI/verification on the hostname.
type Client struct {
	name    string
	http    *http.Client
	timeout time.Duration
	url     string
}

// New builds a client for the given upstream definition.
func New(name, rawURL string, dialIPs []string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("url without host")
	}
	pins := map[string][]string{net.JoinHostPort(host, "443"): dialIPs}
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// Explicitly NO proxy: immune to inherited HTTP_PROXY environment.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ips, ok := pins[addr]; ok && len(ips) > 0 {
				// try pinned IPs in order
				var lastErr error
				for _, ip := range ips {
					c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
					if err == nil {
						return c, nil
					}
					lastErr = err
				}
				return nil, lastErr
			}
			return nil, fmt.Errorf("refusing non-pinned dial %s", addr)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &Client{
		name:    name,
		url:     rawURL,
		timeout: timeout,
		http:    &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // no redirects for DNS queries
		}},
	}, nil
}

// Name returns the upstream display name.
func (c *Client) Name() string { return c.name }

// Exchange sends the wire query and returns the wire response.
func (c *Client) Exchange(ctx context.Context, wire []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("upstream %s: http %d", c.name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) < 12 {
		return nil, resp.StatusCode, fmt.Errorf("upstream %s: short body %d", c.name, len(body))
	}
	return body, resp.StatusCode, nil
}
