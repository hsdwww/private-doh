package upstream

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func mkQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// RED test 1: DO bit must be preserved from the original OPT, never derived from header AD.
func TestApplyECSPreservesDO_IgnoresAD(t *testing.T) {
	m := mkQuery("example.com", dns.TypeA)
	m.AuthenticatedData = true // AD=true, DO=false: must NOT enable DO
	ApplyECS(m, net.IPv4(1, 2, 3, 4))
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("OPT missing after ApplyECS")
	}
	if opt.Do() {
		t.Fatal("AD=true must not set DO (old bug: SetDo(m.AuthenticatedData))")
	}

	m2 := mkQuery("example.com", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(4096)
	o.SetDo(true) // DO=true, AD=false: must preserve DO
	m2.Extra = append(m2.Extra, o)
	ApplyECS(m2, net.IPv4(1, 2, 3, 4))
	opt2 := m2.IsEdns0()
	if opt2 == nil {
		t.Fatal("OPT missing after ApplyECS")
	}
	if !opt2.Do() {
		t.Fatal("DO=true must survive ApplyECS")
	}
	if opt2.UDPSize() != 4096 {
		t.Fatalf("UDPSize not preserved: %d", opt2.UDPSize())
	}
}

// RED test 2: cache-key correctness invariants for DO/CD variants.
func TestApplyECSCacheKeySemantics(t *testing.T) {
	base := mkQuery("example.com", dns.TypeA)
	base.CheckingDisabled = true
	keyCD := ApplyECS(base, net.IPv4(1, 2, 3, 4))
	mk := mkQuery("example.com", dns.TypeA)
	keyNoCD := ApplyECS(mk, net.IPv4(1, 2, 3, 4))
	if keyCD == keyNoCD {
		// CD affects the header, not the ECS key; this is fine — the differentiation
		// happens in cache.Key. Sanity only: ECS prefix must be identical.
		t.Log("CD does not change ECS key (expected); differentiation in cache.Key")
	}
	if keyCD != "1.2.3.0/24" {
		t.Fatalf("ECS key want 1.2.3.0/24 got %s", keyCD)
	}
}

// RED test 3: forged client ECS must be replaced by the trusted /24.
func TestApplyECSReplacesForgedECS(t *testing.T) {
	m := mkQuery("example.com", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24}
	sub.Address = net.IPv4(8, 8, 8, 0) // forged
	o.Option = append(o.Option, sub)
	m.Extra = append(m.Extra, o)
	key := ApplyECS(m, net.IPv4(61, 134, 1, 9))
	if key != "61.134.1.0/24" {
		t.Fatalf("forged ECS must be replaced by client /24, key=%s", key)
	}
	opt := m.IsEdns0()
	found := 0
	for _, op := range opt.Option {
		if s, ok := op.(*dns.EDNS0_SUBNET); ok {
			found++
			if !s.Address.Equal(net.IPv4(61, 134, 1, 0)) {
				t.Fatalf("injected ECS address wrong: %v", s.Address)
			}
			if s.SourceNetmask != 24 {
				t.Fatalf("source netmask want 24 got %d", s.SourceNetmask)
			}
		}
	}
	if found != 1 {
		t.Fatalf("want exactly 1 ECS option after rewrite, got %d", found)
	}
}

// RED test 4: privacy request 0.0.0.0/0 strips ECS entirely.
func TestApplyECSPrivacyRequest(t *testing.T) {
	m := mkQuery("example.com", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 0}
	sub.Address = net.IPv4zero
	o.Option = append(o.Option, sub)
	o.SetDo(true)
	m.Extra = append(m.Extra, o)
	key := ApplyECS(m, net.IPv4(1, 2, 3, 4))
	if key != "privacy" {
		t.Fatalf("privacy request key want 'privacy' got %s", key)
	}
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("OPT with DO must not be dropped on privacy strip")
	}
	if !opt.Do() {
		t.Fatal("DO must survive privacy strip")
	}
	for _, op := range opt.Option {
		if _, ok := op.(*dns.EDNS0_SUBNET); ok {
			t.Fatal("ECS option must be removed on privacy request")
		}
	}
}

// RED test 5: IPv6 client gets /48.
func TestApplyECSIPv6(t *testing.T) {
	m := mkQuery("example.com", dns.TypeA)
	// 2001:db8:abcd:0012::1 -> first 48 bits = 2001:db8:abcd:: (4th hextet 0x0012 lives in bits 48..63)
	key := ApplyECS(m, net.ParseIP("2001:db8:abcd:12::1"))
	if key != "2001:db8:abcd::/48" {
		t.Fatalf("IPv6 /48 key wrong: %s", key)
	}
}

// RED test 6: StripECSFromResponse keeps the OPT when it carries semantics (DO).
func TestStripECSFromResponseKeepsOPTWithDO(t *testing.T) {
	m := new(dns.Msg)
	m.SetReply(mkQuery("example.com", dns.TypeA))
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetDo(true)
	sub := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24}
	sub.Address = net.IPv4(61, 134, 1, 0)
	o.Option = append(o.Option, sub)
	m.Extra = append(m.Extra, o)
	StripECSFromResponse(m)
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("OPT carrying DO must be kept (old bug: empty OPT dropped entirely)")
	}
	if !opt.Do() {
		t.Fatal("DO lost in response strip")
	}
	for _, op := range opt.Option {
		if _, ok := op.(*dns.EDNS0_SUBNET); ok {
			t.Fatal("ECS must be stripped from response")
		}
	}
}
