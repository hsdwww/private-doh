// Package upstream - ecs.go: EDNS Client Subnet rewriting per client IP.
package upstream

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// privacySubnet is the sentinel for client-requested "no ECS" (0.0.0.0/0).
const privacySubnet = "0.0.0.0/0"

// NormalizeClientIP unmaps IPv4-mapped IPv6 and returns the plain IP.
func NormalizeClientIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// ApplyECS rewrites the query's EDNS0 options:
//   - keeps DO/DNSSEC bits
//   - removes client-supplied non-zero ECS (forged or real)
//   - honors explicit 0.0.0.0/0 as "no ECS" (privacy request)
//   - otherwise injects client /24 (IPv4) or /48 (IPv6)
//
// Returns the ECS cache-key string: the masked prefix or "none".
func ApplyECS(m *dns.Msg, clientIP net.IP) string {
	addr, ok := netip.AddrFromSlice(NormalizeClientIP(clientIP))
	if !ok {
		return "none"
	}

	// detect existing ECS option
	var opt *dns.OPT
	var existing *dns.EDNS0_SUBNET
	if e := m.IsEdns0(); e != nil {
		opt = e
		for _, o := range e.Option {
			if sub, isSub := o.(*dns.EDNS0_SUBNET); isSub {
				existing = sub
				break
			}
		}
	}

	// privacy request: client sent 0.0.0.0/0 -> strip ECS entirely
	if existing != nil && isPrivacyECS(existing) {
		stripECS(opt)
		return "privacy"
	}

	// capture semantics from the CLIENT's original OPT before replacing it:
	// DO must come from the OPT record, never from the header AD bit (different fields).
	do := false
	udpSize := uint16(1232)
	if original := m.IsEdns0(); original != nil {
		do = original.Do()
		udpSize = original.UDPSize()
	}

	var bits int
	var family uint16
	if addr.Is4() {
		bits = 24
		family = 1
	} else {
		bits = 48
		family = 2
	}
	prefix := netip.PrefixFrom(addr, bits).Masked()

	// rebuild a single OPT with only our ECS (drop padding & unknown opts)
	newOpt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	newOpt.SetUDPSize(udpSize)
	newOpt.SetDo(do)
	ecs := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(bits), SourceScope: 0}
	ecs.Address = net.IP(prefix.Addr().AsSlice())
	newOpt.Option = append(newOpt.Option, ecs)
	replaceOPT(m, newOpt)
	return prefix.String()
}

// isPrivacyECS reports 0.0.0.0/0 style "disable ECS" requests.
func isPrivacyECS(e *dns.EDNS0_SUBNET) bool {
	return e.SourceNetmask == 0 || (e.Address != nil && e.Address.Equal(net.IPv4zero))
}

// stripECS removes all ECS options from the OPT record.
func stripECS(opt *dns.OPT) {
	if opt == nil {
		return
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isSub := o.(*dns.EDNS0_SUBNET); !isSub {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
}

// replaceOPT swaps the single OPT record in Extra.
func replaceOPT(m *dns.Msg, newOpt *dns.OPT) {
	extra := make([]dns.RR, 0, len(m.Extra)+1)
	for _, rr := range m.Extra {
		if _, isOPT := rr.(*dns.OPT); isOPT {
			continue
		}
		extra = append(extra, rr)
	}
	m.Extra = append(extra, newOpt)
}

// StripECSFromResponse removes gateway-injected ECS from responses to clients.
// The OPT record itself is kept even when empty of options: it may carry DO,
// extended RCODE or UDP-size semantics that must survive the strip.
func StripECSFromResponse(m *dns.Msg) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	stripECS(opt)
}
