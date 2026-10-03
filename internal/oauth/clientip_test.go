package oauth

import (
	"fmt"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func mustProxies(t testing.TB, cidrs ...string) trustedProxies {
	t.Helper()
	p, err := parseTrustedProxies(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseTrustedProxiesRefusesBadEntries(t *testing.T) {
	for _, bad := range [][]string{{"nope"}, {"10.0.0.1/8"}, {"0.0.0.0/0"}} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestClientIP(t *testing.T) {
	caddy := mustProxies(t, "172.18.0.0/16", "fd00::/64")
	for name, tc := range map[string]struct {
		proxies trustedProxies
		remote  string
		xff     []string
		want    string
	}{
		"no proxies, xff ignored":           {nil, "203.0.113.7:4000", []string{"198.51.100.1"}, "203.0.113.7"},
		"untrusted peer, spoofed xff":       {caddy, "203.0.113.7:4000", []string{"198.51.100.1"}, "203.0.113.7"},
		"trusted peer, right-most entry":    {caddy, "172.18.0.2:4000", []string{"198.51.100.1, 203.0.113.9"}, "203.0.113.9"},
		"trusted peer, spoof on the left":   {caddy, "172.18.0.2:4000", []string{"198.51.100.1", "203.0.113.9"}, "203.0.113.9"},
		"trusted chain skipped":             {caddy, "172.18.0.2:4000", []string{"203.0.113.9, 172.18.0.3"}, "203.0.113.9"},
		"trusted peer, no xff":              {caddy, "172.18.0.2:4000", nil, "172.18.0.2"},
		"trusted peer, garbage right-most":  {caddy, "172.18.0.2:4000", []string{"203.0.113.9, not-an-ip"}, "172.18.0.2"},
		"ipv6 peer trusted":                 {caddy, "[fd00::5]:4000", []string{"2001:db8::1"}, "2001:db8::1"},
		"ipv4-mapped peer is unmapped":      {mustProxies(t, "127.0.0.0/8"), "[::ffff:127.0.0.1]:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		"ipv4-mapped xff entry is unmapped": {caddy, "172.18.0.2:4000", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
	} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = tc.remote
		for _, v := range tc.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := tc.proxies.clientIP(r); got.String() != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

func TestIPLimiterKeepsSourcesApart(t *testing.T) {
	l := newIPLimiter(time.Hour, 2, 16)
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	for i := 0; i < 2; i++ {
		if _, ok := l.allow(a); !ok {
			t.Fatalf("a attempt %d refused", i)
		}
	}
	if d, ok := l.allow(a); ok || d <= 0 {
		t.Fatalf("a over its burst: %v %v", d, ok)
	}
	if _, ok := l.allow(b); !ok {
		t.Fatal("b refused because a exhausted its bucket")
	}
}

// IPv6 sources share a bucket per /64: one host usually holds the whole
// /64, so per-address buckets would give it 2^64 of them.
func TestIPLimiterGroupsIPv6By64(t *testing.T) {
	l := newIPLimiter(time.Hour, 1, 16)
	if _, ok := l.allow(netip.MustParseAddr("2001:db8:1:2::1")); !ok {
		t.Fatal("first refused")
	}
	if _, ok := l.allow(netip.MustParseAddr("2001:db8:1:2:ffff::9")); ok {
		t.Fatal("same /64 got a fresh bucket")
	}
	if _, ok := l.allow(netip.MustParseAddr("2001:db8:1:3::1")); !ok {
		t.Fatal("another /64 refused")
	}
}

func TestIPLimiterIsBounded(t *testing.T) {
	l := newIPLimiter(time.Hour, 1, 8)
	first := netip.MustParseAddr("198.51.100.1")
	_, _ = l.allow(first)
	for i := 0; i < 100; i++ {
		_, _ = l.allow(netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i)))
		if n := l.len(); n > 8 {
			t.Fatalf("%d buckets, bound is 8", n)
		}
	}
	// The least recently used bucket was evicted, so first starts fresh.
	if _, ok := l.allow(first); !ok {
		t.Fatal("evicted source still limited")
	}
	// A recently used one is kept.
	recent := netip.MustParseAddr("203.0.113.99")
	if _, ok := l.allow(recent); ok {
		t.Fatal("recent source lost its bucket")
	}
}

// clientIP reads an untrusted header: whatever it holds, the result is the
// peer or an address that is not a trusted proxy, and an untrusted peer is
// never overridden.
func FuzzClientIP(f *testing.F) {
	f.Add("172.18.0.2:4000", "198.51.100.1, 203.0.113.9")
	f.Add("172.18.0.2:4000", "203.0.113.9, 172.18.0.3")
	f.Add("203.0.113.7:4000", "198.51.100.1")
	f.Add("[fd00::5]:4000", "::ffff:203.0.113.9, fe80::1%eth0")
	f.Add("[::ffff:172.18.0.2]:1", ",,, ,")
	proxies := mustProxies(f, "172.18.0.0/16", "fd00::/64")
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		got := proxies.clientIP(r)
		peer := remoteAddr(remote)
		if !proxies.trusts(peer) && got != peer {
			t.Fatalf("untrusted peer %s overridden by %s", peer, got)
		}
		if got != peer && (proxies.trusts(got) || !got.IsValid() || got.Is4In6() || got.Zone() != "") {
			t.Fatalf("result %s from header %q", got, xff)
		}
	})
}
