package oauth

import (
	"container/list"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"golang.org/x/time/rate"
)

const (
	// ipLimiterSize bounds the per-source buckets of each limiter. A full
	// table evicts the least recently used source; an attacker rotating
	// addresses can evict a bucket, which only resets that source, and the
	// global limiter behind it still caps the total.
	ipLimiterSize = 4096
	// maxForwardedHops bounds the X-Forwarded-For walk.
	maxForwardedHops = 32
)

// trustedProxies are the reverse proxies whose X-Forwarded-For entry is
// believed (config trusted_proxies). Empty means the TCP peer is the client.
type trustedProxies []netip.Prefix

// parseTrustedProxies validates with config.CheckTrustedProxy, the single
// definition of the syntax.
func parseTrustedProxies(cidrs []string) (trustedProxies, error) {
	p := make(trustedProxies, 0, len(cidrs))
	for i, c := range cidrs {
		if msg := config.CheckTrustedProxy(c); msg != "" {
			return nil, fmt.Errorf("trusted_proxies[%d] (%q): %s", i, c, msg)
		}
		n, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies[%d] (%q): %w", i, c, err)
		}
		p = append(p, n)
	}
	return p, nil
}

func (p trustedProxies) trusts(a netip.Addr) bool {
	for _, n := range p {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address a request's rate limits are keyed on. If the TCP
// peer is not a trusted proxy, it is the peer and X-Forwarded-For is
// ignored (any client can write that header). If it is, the header is read
// from the right: each trusted proxy appends the address it received from,
// so the right-most entry that is not itself a trusted proxy is the client.
// Entries to the left of it were written by the client and are never read.
// A malformed entry stops the walk and the peer is used, so garbage cannot
// select a bucket. IPv4-mapped IPv6 forms are unmapped and zones dropped,
// so one source has one spelling.
func (p trustedProxies) clientIP(r *http.Request) netip.Addr {
	peer := remoteAddr(r.RemoteAddr)
	if !peer.IsValid() || !p.trusts(peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i, n := len(hops)-1, 0; i >= 0 && n < maxForwardedHops; i, n = i-1, n+1 {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		a = a.Unmap().WithZone("")
		if !p.trusts(a) {
			return a
		}
	}
	return peer
}

func remoteAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

// ipLimiter is a token bucket per source, bounded by an LRU. IPv4 sources
// are keyed per address, IPv6 per /64 (a single host usually controls a
// whole /64). An unparsable source shares one bucket (the zero prefix).
type ipLimiter struct {
	mu    sync.Mutex
	every time.Duration
	burst int
	size  int
	order *list.List // of *ipBucket, most recently used first
	byKey map[netip.Prefix]*list.Element
}

type ipBucket struct {
	key netip.Prefix
	lim *rate.Limiter
}

func newIPLimiter(every time.Duration, burst, size int) *ipLimiter {
	return &ipLimiter{every: every, burst: burst, size: size, order: list.New(), byKey: map[netip.Prefix]*list.Element{}}
}

func sourceKey(a netip.Addr) netip.Prefix {
	bits := 64
	if a.Is4() {
		bits = 32
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// allow takes one token from a's bucket. When the bucket is empty nothing
// is taken and the wait until the next token is returned.
func (l *ipLimiter) allow(a netip.Addr) (time.Duration, bool) {
	key := sourceKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *ipBucket
	if el, ok := l.byKey[key]; ok {
		l.order.MoveToFront(el)
		b = el.Value.(*ipBucket)
	} else {
		b = &ipBucket{key: key, lim: rate.NewLimiter(rate.Every(l.every), l.burst)}
		l.byKey[key] = l.order.PushFront(b)
		for l.order.Len() > l.size {
			old := l.order.Back()
			l.order.Remove(old)
			delete(l.byKey, old.Value.(*ipBucket).key)
		}
	}
	return reserveNow(b.lim)
}

func (l *ipLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// reserveNow takes a token only if one is available now; otherwise it takes
// nothing and returns the wait (at least one second, for Retry-After).
func reserveNow(lim *rate.Limiter) (time.Duration, bool) {
	res := lim.Reserve()
	if !res.OK() {
		return time.Minute, false
	}
	if d := res.Delay(); d > 0 {
		res.Cancel()
		return max(d, time.Second), false
	}
	return 0, true
}

// retryAfter formats a wait as whole seconds, rounded up.
func retryAfter(d time.Duration) string {
	return fmt.Sprint(int64((d + time.Second - 1) / time.Second))
}
