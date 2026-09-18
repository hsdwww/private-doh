// Package cache: ECS-partitioned TTL-aware DNS message cache.
package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// entry holds a deep-copied response and its expiry.
type entry struct {
	msg       *dns.Msg
	storedAt  time.Time
	ttl       time.Duration
	ecsKey    string
}

// Cache is a bounded LRU-ish map keyed by (qname,qtype,qclass,ecs,flags).
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*entry
	order   []string // insertion order for eviction
	now     func() time.Time
}

// New creates a cache with max entries.
func New(max int) *Cache {
	return &Cache{max: max, entries: map[string]*entry{}, now: time.Now}
}

// Key builds the cache key from a query message and ECS partition.
func Key(q *dns.Msg, ecs string) string {
	qn := q.Question[0]
	var sb strings.Builder
	sb.Grow(64)
	sb.WriteString(strings.ToLower(qn.Name))
	sb.WriteByte('|')
	writeUint(&sb, uint32(qn.Qtype))
	sb.WriteByte('|')
	writeUint(&sb, uint32(qn.Qclass))
	sb.WriteByte('|')
	sb.WriteString(ecs)
	sb.WriteByte('|')
	writeUint(&sb, bools(q.RecursionDesired, q.CheckingDisabled))
	writeUint(&sb, bools(hasDO(q), false))
	return sb.String()
}

func bools(a, b bool) uint32 {
	v := uint32(0)
	if a {
		v |= 2
	}
	if b {
		v |= 1
	}
	return v
}

func hasDO(q *dns.Msg) bool {
	if opt := q.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

func writeUint(sb *strings.Builder, v uint32) {
	if v == 0 {
		sb.WriteByte('0')
		return
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	sb.Write(buf[i:])
}

// Get returns a deep copy with TTLs decremented, or nil on miss/expiry.
func (c *Cache) Get(key string, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	if !now.Before(e.storedAt.Add(e.ttl)) { // expired at or before the expiry instant
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	elapsed := now.Sub(e.storedAt)
	msg := e.msg.Copy()
	c.mu.Unlock()
	decrementTTL(msg, elapsed)
	return msg, true
}

// Put stores a copy of msg with the given ttl (already clamped by caller).
func (c *Cache) Put(key string, msg *dns.Msg, ttl time.Duration, now time.Time) {
	if msg == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		if _, exists := c.entries[key]; !exists {
			// evict oldest by insertion order; compact stale keys along the way
			for len(c.order) > 0 && len(c.entries) >= c.max {
				old := c.order[0]
				c.order = c.order[1:]
				if _, ok := c.entries[old]; ok {
					delete(c.entries, old)
					break
				}
			}
		}
	}
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
	}
	c.entries[key] = &entry{msg: msg.Copy(), storedAt: now, ttl: ttl}
}

// Len returns current entry count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// InvalidateAll clears every entry (used on rules generation change).
func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*entry{}
	c.order = nil
}

// decrementTTL subtracts elapsed from all RR TTLs (never below zero)
// without touching OPT pseudo-RR TTL bits.
func decrementTTL(m *dns.Msg, elapsed time.Duration) {
	sec := int64(elapsed.Seconds())
	if sec <= 0 {
		return
	}
	dec := func(rr dns.RR) {
		h := rr.Header()
		if h.Rrtype != dns.TypeOPT {
			if int64(h.Ttl) > sec {
				h.Ttl -= uint32(sec)
			} else {
				h.Ttl = 0
			}
		}
	}
	for _, rr := range m.Answer {
		dec(rr)
	}
	for _, rr := range m.Ns {
		dec(rr)
	}
	for _, rr := range m.Extra {
		dec(rr)
	}
}

// ResponseTTL computes the min RR TTL of the message including the Additional
// section (0 if none or any zero), used by callers to decide cacheability.
// A zero TTL anywhere means the package must not be cached at all.
func ResponseTTL(m *dns.Msg) time.Duration {
	minTTL := time.Duration(0)
	seen := false
	scan := func(rr dns.RR) {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			return
		}
		t := time.Duration(h.Ttl) * time.Second
		if h.Ttl == 0 {
			minTTL = 0
			seen = true
			return
		}
		if !seen || t < minTTL {
			minTTL = t
			seen = true
		}
	}
	for _, rr := range m.Answer {
		scan(rr)
	}
	for _, rr := range m.Ns {
		scan(rr)
	}
	for _, rr := range m.Extra {
		scan(rr)
	}
	if !seen {
		return 0
	}
	return minTTL
}

// NegativeTTL extracts min(SOA TTL, SOA MINIMUM) capped at 3600s.
func NegativeTTL(m *dns.Msg) time.Duration {
	var soa *dns.SOA
	for _, rr := range m.Ns {
		if s, ok := rr.(*dns.SOA); ok {
			soa = s
			break
		}
	}
	if soa == nil {
		return 0
	}
	t1 := time.Duration(soa.Hdr.Ttl) * time.Second
	t2 := time.Duration(soa.Minttl) * time.Second
	min := t1
	if t2 < min {
		min = t2
	}
	if min > 3600*time.Second {
		min = 3600 * time.Second
	}
	return min
}
