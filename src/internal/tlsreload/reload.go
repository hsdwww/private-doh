// Package tlsreload: hot certificate loading without restarts.
package tlsreload

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// NewTLSConfig builds a tls.Config with dynamic GetCertificate.
func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil },
	}
	current.Store(&cert)
	return cfg, nil
}

var current atomic.Pointer[tls.Certificate]

// Watch polls the current symlink and hot-swaps the certificate.
func Watch(tlsDir string, cfg *tls.Config) {
	var last string
	for {
		time.Sleep(60 * time.Second)
		target, err := os.Readlink(filepath.Join(tlsDir, "current"))
		if err != nil || target == last {
			continue
		}
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(tlsDir, target, "fullchain.pem"),
			filepath.Join(tlsDir, target, "privkey.pem"),
		)
		if err != nil {
			continue // keep old cert on failure
		}
		// sanity: must be valid now
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
			continue
		}
		current.Store(&cert)
		last = target
	}
}
