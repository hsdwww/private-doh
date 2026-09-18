package resolve

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"private-doh/internal/filter"
)

type fakeUp struct {
	name    string
	calls   int
	fail    bool
	answers []net.IP
	mu      sync.Mutex
}

func (f *fakeUp) Exchange(ctx context.Context, wire []byte) ([]byte, int, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.fail {
		return nil, 0, context.DeadlineExceeded
	}
	q := new(dns.Msg)
	if err := q.Unpack(wire); err != nil {
		return nil, 0, err
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(93, 184, 216, 34).To4(),
	})
	out, err := m.Pack()
	return out, 200, err
}
func (f *fakeUp) Name() string { return f.name }
func (f *fakeUp) count() int   { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func newRes(t *testing.T, primary, secondary UpstreamClient) *Resolver {
	return New(primary, secondary, Config{BlockHTTPSRR: true, FilterOn: false, TotalBudget: 2 * time.Second})
}

func qmsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func TestType65LocalNoerror(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := newRes(t, p, p)
	resp := r.Resolve(qmsg("example.com", dns.TypeHTTPS), net.IPv4(1, 2, 3, 4))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("type65 want NOERROR empty, got rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	if p.count() != 0 {
		t.Fatal("type65 must not hit upstream")
	}
}

func TestCacheHitSingleUpstreamCall(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := newRes(t, p, p)
	ip := net.IPv4(61, 134, 1, 2)
	r.Resolve(qmsg("www.taobao.com", dns.TypeA), ip)
	r.Resolve(qmsg("www.taobao.com", dns.TypeA), ip)
	if p.count() != 1 {
		t.Fatalf("upstream called %d times, want 1 (cache)", p.count())
	}
	if r.Stats().CacheHit.Load() != 1 {
		t.Fatal("expected 1 cache hit")
	}
}

func TestECSIsolation(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := newRes(t, p, p)
	r.Resolve(qmsg("cdn.example.net", dns.TypeA), net.IPv4(61, 134, 1, 2)) // taiyuan /24
	r.Resolve(qmsg("cdn.example.net", dns.TypeA), net.IPv4(113, 108, 1, 2)) // guangzhou /24
	if p.count() != 2 {
		t.Fatalf("different ECS must not share cache, calls=%d", p.count())
	}
}

func TestFallbackOnPrimaryFailure(t *testing.T) {
	p := &fakeUp{name: "p", fail: true}
	s := &fakeUp{name: "s"}
	r := newRes(t, p, s)
	resp := r.Resolve(qmsg("example.org", dns.TypeA), net.IPv4(1, 2, 3, 4))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("fallback failed: rcode=%d", resp.Rcode)
	}
	if r.Stats().Fallback.Load() != 1 || s.count() != 1 {
		t.Fatal("expected exactly one fallback")
	}
}

func TestBothFailServfail(t *testing.T) {
	p2 := &fakeUp{name: "p2", fail: true}
	s2 := &fakeUp{name: "s2", fail: true}
	r2 := newRes(t, p2, s2)
	resp := r2.Resolve(qmsg("dead.example", dns.TypeA), net.IPv4(1, 2, 3, 4))
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL got %d", resp.Rcode)
	}
}

func TestIDRestored(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := newRes(t, p, p)
	q := qmsg("idcheck.example", dns.TypeA)
	q.Id = 4242
	resp := r.Resolve(q, net.IPv4(1, 2, 3, 4))
	if resp.Id != 4242 {
		t.Fatalf("client ID not restored: %d", resp.Id)
	}
}

func mkFilter(t *testing.T, blocks, allows []string) *filter.List {
	t.Helper()
	l, err := filter.NewList(blocks, allows, "h", "v")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFilterRefused(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := New(p, p, Config{BlockHTTPSRR: true, FilterOn: true, TotalBudget: 2 * time.Second})
	r.SetFilter(mkFilter(t, []string{"*.ads.example.com"}, nil))
	resp := r.Resolve(qmsg("track.ads.example.com", dns.TypeA), net.IPv4(1, 2, 3, 4))
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("ad domain want REFUSED got %d", resp.Rcode)
	}
	if p.count() != 0 {
		t.Fatal("blocked must not hit upstream")
	}
}

func TestConcurrentSingleflight(t *testing.T) {
	p := &fakeUp{name: "p"}
	r := newRes(t, p, p)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Resolve(qmsg("burst.example.io", dns.TypeA), net.IPv4(61, 134, 9, 9))
		}()
	}
	wg.Wait()
	if p.count() != 1 {
		t.Fatalf("20 concurrent same-key requests produced %d upstream calls, want 1", p.count())
	}
}
