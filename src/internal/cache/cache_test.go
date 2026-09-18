package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ipOf(a, b, c, d byte) net.IP { return net.IPv4(a, b, c, d).To4() }

func msgWithTTLs(answerTTL, extraTTL uint32, qname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: qname + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL},
		A:   ipOf(93, 184, 216, 34),
	})
	if extraTTL > 0 {
		m.Extra = append(m.Extra, &dns.A{
			Hdr: dns.RR_Header{Name: "extra." + qname + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: extraTTL},
			A:   ipOf(1, 1, 1, 1),
		})
	}
	return m
}

// RED: mixed 0/300 TTL must NOT be cached (zero TTL is the true minimum).
func TestResponseTTLZeroIsMinimum(t *testing.T) {
	m := msgWithTTLs(300, 0, "mixed.example")
	m.Extra = nil
	// add one zero-TTL record in Answer alongside a 300
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "mixed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   ipOf(93, 184, 216, 35),
	})
	ttl := ResponseTTL(m)
	if ttl != 0 {
		t.Fatalf("zero-TTL RR must make package TTL 0, got %v", ttl)
	}
}

// RED: Additional-section shorter TTL limits package lifetime.
func TestResponseTTLIncludesExtra(t *testing.T) {
	m := msgWithTTLs(300, 30, "extra.example")
	ttl := ResponseTTL(m)
	if ttl != 30*time.Second {
		t.Fatalf("Additional shorter TTL must cap package, got %v", ttl)
	}
}

// RED: OPT must not be treated as a TTL-bearing RR.
func TestResponseTTLSkipsOPT(t *testing.T) {
	m := msgWithTTLs(300, 0, "opt.example")
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Ttl: 1}} // Ttl field carries flags, not seconds
	m.Extra = append(m.Extra, opt)
	ttl := ResponseTTL(m)
	if ttl != 300*time.Second {
		t.Fatalf("OPT flags must not affect TTL, got %v", ttl)
	}
}

// RED: expiry instant must be a miss (was: hits for one instant).
func TestGetExpiryInstantIsMiss(t *testing.T) {
	c := New(10)
	now := time.Now()
	c.Put("k", msgWithTTLs(100, 0, "exp.example"), 50*time.Second, now)
	if _, ok := c.Get("k", now.Add(50*time.Second)); ok {
		t.Fatal("at exact expiry must be miss (!now.Before(expiry))")
	}
}

// RED: capacity must actually be enforced (wired from config).
func TestCapacityEnforced(t *testing.T) {
	c := New(3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		c.Put(string(rune('a'+i)), msgWithTTLs(100, 0, "cap.example"), time.Minute, now)
	}
	if c.Len() > 3 {
		t.Fatalf("capacity not enforced: len=%d > 3", c.Len())
	}
}

// RED: returned copies must not share state (TTL decrement isolation).
func TestGetReturnsIsolatedCopy(t *testing.T) {
	c := New(10)
	now := time.Now()
	c.Put("k", msgWithTTLs(300, 0, "copy.example"), time.Minute, now)
	m1, _ := c.Get("k", now.Add(10*time.Second))
	m2, _ := c.Get("k", now.Add(10*time.Second))
	if m1.Answer[0].Header().Ttl != 290 || m2.Answer[0].Header().Ttl != 290 {
		t.Fatalf("copy isolation broken: ttl1=%d ttl2=%d", m1.Answer[0].Header().Ttl, m2.Answer[0].Header().Ttl)
	}
}

// RED: auxiliary order slice must not grow unboundedly across expire/reinsert cycles.
func TestOrderBoundedAcrossCycles(t *testing.T) {
	c := New(4)
	base := time.Now()
	for round := 0; round < 50; round++ {
		now := base.Add(time.Duration(round) * time.Hour)
		for i := 0; i < 4; i++ {
			c.Put("k"+string(rune('a'+i)), msgWithTTLs(100, 0, "cyc.example"), time.Second, now.Add(-2*time.Second))
		}
	}
	if len(c.order) > 16 { // generous bound: cycles must compact
		t.Fatalf("order slice grew unboundedly: %d", len(c.order))
	}
}
