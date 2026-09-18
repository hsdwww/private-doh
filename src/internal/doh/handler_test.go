package doh

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const testToken = "0123456789abcdef0123456789abcdef01234567"

type fakeResolver struct {
	called int
	lastIP string
}

func (f *fakeResolver) Resolve(q *dns.Msg, ip net.IP) *dns.Msg {
	f.called++
	f.lastIP = ip.String()
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(1, 2, 3, 4).To4(),
	})
	return m
}

func newSrv(t *testing.T) (*httptest.Server, *fakeResolver) {
	t.Helper()
	fr := &fakeResolver{}
	h := NewHandler(testToken, fr)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, fr
}

func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func postQuery(t *testing.T, url string, wire []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPostQuery(t *testing.T) {
	srv, fr := newSrv(t)
	resp := postQuery(t, srv.URL+"/dns/"+testToken, buildQuery(t, "example.com", dns.TypeA))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Fatalf("ct %s", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control %s", cc)
	}
	if fr.called != 1 {
		t.Fatalf("resolver called %d", fr.called)
	}
}

func TestGetQuery(t *testing.T) {
	srv, fr := newSrv(t)
	q := base64.RawURLEncoding.EncodeToString(buildQuery(t, "example.org", dns.TypeA))
	resp, err := http.Get(srv.URL + "/dns/" + testToken + "?dns=" + q)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || fr.called != 1 {
		t.Fatalf("status %d called %d", resp.StatusCode, fr.called)
	}
}

func TestWrongToken404(t *testing.T) {
	srv, _ := newSrv(t)
	resp, err := http.Get(srv.URL + "/dns/wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("want 404 got %d", resp.StatusCode)
	}
}

func TestWrongContentType415(t *testing.T) {
	srv, _ := newSrv(t)
	resp, err := http.Post(srv.URL+"/dns/"+testToken, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 415 {
		t.Fatalf("want 415 got %d", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _ := newSrv(t)
	req, _ := http.NewRequest("DELETE", srv.URL+"/dns/"+testToken, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("want 405 got %d", resp.StatusCode)
	}
}

func TestMalformedDNS400(t *testing.T) {
	srv, _ := newSrv(t)
	resp := postQuery(t, srv.URL+"/dns/"+testToken, []byte("garbage"))
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400 got %d", resp.StatusCode)
	}
}

func TestOversizeBodyRejected(t *testing.T) {
	srv, _ := newSrv(t)
	big := make([]byte, 8192)
	resp := postQuery(t, srv.URL+"/dns/"+testToken, big)
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400 got %d", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	fr := &fakeResolver{}
	h := NewHandler(testToken, fr)
	h.ips = newIPLimiter(1, 3)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	codes := map[int]int{}
	for i := 0; i < 8; i++ {
		resp := postQuery(t, srv.URL+"/dns/"+testToken, buildQuery(t, "example.com", dns.TypeA))
		resp.Body.Close()
		codes[resp.StatusCode]++
	}
	if codes[429] == 0 || codes[200] == 0 {
		t.Fatalf("expected mix of 200/429, got %v", codes)
	}
}

func TestANYNotImplemented(t *testing.T) {
	srv, fr := newSrv(t)
	resp := postQuery(t, srv.URL+"/dns/"+testToken, buildQuery(t, "example.com", dns.TypeANY))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m dns.Msg
	if err := m.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if m.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("ANY should get NOTIMPL, got %d", m.Rcode)
	}
	if fr.called != 0 {
		t.Fatal("ANY must not reach resolver")
	}
}
