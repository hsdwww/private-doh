// Package doh implements the RFC 8484 HTTPS handler: auth, validation, limits.
package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver is the DNS resolution callback the handler delegates to.
type Resolver interface {
	// Resolve takes a validated query message and the client IP, returns the response.
	Resolve(query *dns.Msg, clientIP net.IP) *dns.Msg
}

// Handler serves DoH GET/POST on the token path.
type Handler struct {
	token     string
	resolver  Resolver
	ips       *ipLimiter
	maxBody   int
}

// NewHandler builds the handler.
func NewHandler(token string, r Resolver) *Handler {
	return &Handler{
		token:    token,
		resolver: r,
		ips:      newIPLimiter(10, 100), // 10 r/s, burst 100
		maxBody:  4096,
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns/"+h.token {
		http.NotFound(w, r)
		return
	}
	ip := clientIP(r)
	if !h.ips.allow(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" || len(q) > 4096 {
			http.Error(w, "bad dns param", http.StatusBadRequest)
			return
		}
		wire, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
		h.serveWire(w, wire, ip)
	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/dns-message" {
			http.Error(w, "bad content-type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(h.maxBody))
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		h.serveWire(w, wire, ip)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveWire validates the DNS message and resolves.
func (h *Handler) serveWire(w http.ResponseWriter, wire []byte, ip net.IP) {
	w.Header().Set("Cache-Control", "no-store")
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		http.Error(w, "malformed dns", http.StatusBadRequest)
		return
	}
	if msg.Response || msg.Opcode != dns.OpcodeQuery || len(msg.Question) != 1 {
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeFormatError) // FORMERR
		h.writeDNS(w, resp)
		return
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeANY || q.Qclass != dns.ClassINET {
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeNotImplemented)
		h.writeDNS(w, resp)
		return
	}
	resp := h.resolver.Resolve(msg, ip)
	h.writeDNS(w, resp)
}

// writeDNS packs and writes the response message.
func (h *Handler) writeDNS(w http.ResponseWriter, m *dns.Msg) {
	packed, err := m.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}

// clientIP extracts the real peer from the TCP connection.
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// ipLimiter is a simple per-IP token bucket.
type ipLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(rate int, burst int) *ipLimiter {
	return &ipLimiter{rate: float64(rate), burst: float64(burst), buckets: map[string]*bucket{}, lastGC: time.Now()}
}

func (l *ipLimiter) allow(ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := ip.String()
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= 100000 { // hard cap
			l.gc(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc removes idle buckets older than 10 minutes.
func (l *ipLimiter) gc(now time.Time) {
	for k, v := range l.buckets {
		if now.Sub(v.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

var _ = fmt.Sprintf // keep fmt if unused later
