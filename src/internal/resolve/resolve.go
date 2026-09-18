// Package resolve: orchestration of filter -> cache -> upstreams -> ECS.
package resolve

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"private-doh/internal/cache"
	"private-doh/internal/doh"
	"private-doh/internal/filter"
	"private-doh/internal/upstream"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// UpstreamClient is the interface for one upstream (test double friendly).
type UpstreamClient interface {
	Exchange(ctx context.Context, wire []byte) ([]byte, int, error)
	Name() string
}

// Stats aggregates counters for /stats.
type Stats struct {
	Queries    atomic.Int64
	Filtered   atomic.Int64
	Type65     atomic.Int64
	CacheHit   atomic.Int64
	CacheMiss  atomic.Int64
	UpOK       atomic.Int64
	UpFail     atomic.Int64
	Fallback   atomic.Int64
	ServFail   atomic.Int64
}

// Resolver is the core engine.
type Resolver struct {
	filter     atomic.Pointer[filter.List]
	cache      *cache.Cache
	sfGroup    singleflight.Group
	primary    UpstreamClient
	secondary  UpstreamClient
	stats      Stats
	cfg        Config
	rulesGen   atomic.Int64
	mu         sync.RWMutex
}

// Config for the resolver.
type Config struct {
	BlockHTTPSRR    bool
	FilterOn        bool
	TotalBudget     time.Duration
	MaxCacheEntries int // <=0 falls back to 5000
}

// New builds a resolver.
func New(primary, secondary UpstreamClient, cfg Config) *Resolver {
	maxCache := cfg.MaxCacheEntries
	if maxCache <= 0 {
		maxCache = 5000
	}
	r := &Resolver{
		cache:     cache.New(maxCache),
		primary:   primary,
		secondary: secondary,
		cfg:       cfg,
	}
	r.rulesGen.Store(0)
	return r
}

// SetFilter atomically swaps the filter snapshot and bumps the generation,
// invalidating the cache (answers may change under a new ruleset).
func (r *Resolver) SetFilter(l *filter.List) {
	r.filter.Store(l)
	r.rulesGen.Add(1)
	r.cache.InvalidateAll()
}

// FilterSnapshot returns the current list (may be nil if filtering off).
func (r *Resolver) FilterSnapshot() *filter.List { return r.filter.Load() }

// Stats returns a pointer for the admin handler.
func (r *Resolver) Stats() *Stats { return &r.stats }

// CacheLen exposes cache size.
func (r *Resolver) CacheLen() int { return r.cache.Len() }

// Resolve implements doh.Resolver: the per-request pipeline.
func (r *Resolver) Resolve(q *dns.Msg, clientIP net.IP) *dns.Msg {
	r.stats.Queries.Add(1)
	qname := strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))

	// 1. optional type65 suppression policy, only when enabled
	if r.cfg.BlockHTTPSRR && q.Question[0].Qtype == dns.TypeHTTPS {
		r.stats.Type65.Add(1)
		return localPolicyReply(q, dns.RcodeSuccess, 0) // NOERROR/NODATA
	}

	// 2. ad filter on qname
	if r.cfg.FilterOn {
		if l := r.filter.Load(); l != nil {
			if blocked, _ := l.Blocked(qname); blocked {
				r.stats.Filtered.Add(1)
				return localPolicyReply(q, dns.RcodeRefused, 0)
			}
		}
	}

	// 3. ECS partitioning (key) + upstream wire rewrite
	ecsKey := upstream.ApplyECS(q, clientIP)
	ck := cache.Key(q, ecsKey)

	// 4. cache lookup
	if msg, ok := r.cache.Get(ck, time.Now()); ok {
		r.stats.CacheHit.Add(1)
		msg.Id = q.Id
		return finalize(msg, q)
	}
	r.stats.CacheMiss.Add(1)

	// 5. singleflight upstream fetch
	// Double-check the cache INSIDE the flight: stragglers that missed the
	// outer Get just before the first Put would otherwise start a second
	// upstream call for the same key (caught by -race scheduling).
	v, err, _ := r.sfGroup.Do(ck, func() (interface{}, error) {
		if msg, ok := r.cache.Get(ck, time.Now()); ok {
			r.stats.CacheMiss.Add(-1) // reclassify: it was a hit after all
			r.stats.CacheHit.Add(1)
			return msg, nil
		}
		return r.fetchUpstream(q, ecsKey)
	})
	if err != nil || v == nil {
		r.stats.ServFail.Add(1)
		return servfail(q)
	}
	// deep copy per waiter: the shared result must never be mutated by callers
	resp := v.(*dns.Msg).Copy()
	resp.Id = q.Id
	return finalize(resp, q)
}

// fetchUpstream tries primary then secondary within budget.
func (r *Resolver) fetchUpstream(q *dns.Msg, ecsKey string) (*dns.Msg, error) {
	budget := r.cfg.TotalBudget
	if budget <= 0 {
		budget = 4500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}

	body, _, err := r.primary.Exchange(ctx, wire)
	if err == nil {
		if m, uerr := unpackCheck(body, q); uerr == nil {
			r.stats.UpOK.Add(1)
			r.maybeCache(q, m, cache.Key(q, ecsKey))
			return m, nil
		} else {
			err = uerr
		}
	}
	// fallback
	r.stats.Fallback.Add(1)
	body2, _, err2 := r.secondary.Exchange(ctx, wire)
	if err2 == nil {
		if m, uerr := unpackCheck(body2, q); uerr == nil {
			r.stats.UpOK.Add(1)
			r.maybeCache(q, m, cache.Key(q, ecsKey))
			return m, nil
		}
	}
	r.stats.UpFail.Add(1)
	return nil, fmt.Errorf("both upstreams failed: %v / %v", err, err2)
}

// maybeCache applies the caching policy (positive/negative rules).
func (r *Resolver) maybeCache(q *dns.Msg, m *dns.Msg, key string) {
	if key == "" {
		return
	}
	switch m.Rcode {
	case dns.RcodeSuccess:
		if len(m.Answer) == 0 {
			// NODATA: cache with SOA negative TTL
			if ttl := cache.NegativeTTL(m); ttl > 0 {
				r.cache.Put(key, m, ttl, time.Now())
			}
			return
		}
		ttl := cache.ResponseTTL(m)
		if ttl >= 10*time.Second {
			if ttl > 86400*time.Second {
				ttl = 86400 * time.Second
			}
			r.cache.Put(key, m, ttl, time.Now())
		}
	case dns.RcodeNameError: // NXDOMAIN
		if ttl := cache.NegativeTTL(m); ttl > 0 {
			r.cache.Put(key, m, ttl, time.Now())
		}
	}
}

// unpackCheck validates the upstream response against the question.
func unpackCheck(body []byte, q *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	if m.Rcode == dns.RcodeFormatError || m.Rcode == dns.RcodeNotImplemented {
		return m, nil // valid upstream verdicts
	}
	if m.Truncated {
		return nil, fmt.Errorf("truncated upstream response")
	}
	if len(m.Question) == 0 {
		return nil, fmt.Errorf("no question in response")
	}
	want := strings.ToLower(q.Question[0].Name)
	got := strings.ToLower(m.Question[0].Name)
	if want != got || q.Question[0].Qtype != m.Question[0].Qtype {
		return nil, fmt.Errorf("question mismatch")
	}
	return m, nil
}

// finalize strips gateway-injected ECS from the client-facing response.
func finalize(m *dns.Msg, q *dns.Msg) *dns.Msg {
	upstream.StripECSFromResponse(m)
	return m
}

// localPolicyReply builds a local REFUSED / NOERROR-empty response.
func localPolicyReply(q *dns.Msg, rcode int, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(q, rcode)
	m.RecursionAvailable = true
	m.AuthenticatedData = false
	return m
}

// servfail builds SERVFAIL.
func servfail(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(q, dns.RcodeServerFailure)
	return m
}

var _ = net.IPv4zero
var _ doh.Resolver = (*Resolver)(nil)
