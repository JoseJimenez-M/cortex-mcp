package oauth

import (
	"container/list"
	"context"
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

// sourceCtxKey is the context key under which Service puts the request's
// source address (clientIP), for limits charged below the HTTP layer (the
// CIMD first-fetch budget, reached through the library's client lookup).
type sourceCtxKey struct{}

func withSource(ctx context.Context, a netip.Addr) context.Context {
	return context.WithValue(ctx, sourceCtxKey{}, a)
}

// sourceFrom returns the source put there by withSource, or the zero
// address (one shared bucket) when there is none.
func sourceFrom(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(sourceCtxKey{}).(netip.Addr)
	return a
}

// sourceLabel is the stored form of a source's rate-limit key (sourceKey),
// "" for an unknown source (they share one cap, like they share a bucket).
func sourceLabel(a netip.Addr) string {
	if p := sourceKey(a); p.IsValid() {
		return p.String()
	}
	return ""
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
// are keyed per address, IPv6 per /48: a /48 is a routine allocation (many
// providers hand one to a single customer, and tunnel brokers give them away),
// so keying per /64 would let one attacker look like 65536 sources. An
// unparsable source shares one bucket (the zero prefix).
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
	bits := 48
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
	_, d, ok := l.reserve(a, time.Now())
	return d, ok
}

// reserve is allow at time now, returning the reservation so the caller can
// give the token back with CancelAt(now).
func (l *ipLimiter) reserve(a netip.Addr, now time.Time) (*rate.Reservation, time.Duration, bool) {
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
	return reserveAt(b.lim, now)
}

func (l *ipLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// admitSource charges a's bucket in perIP, then the global bucket. A source
// its own bucket refuses never draws on the global one, so it cannot spend
// the budget of everyone else; and when the global bucket refuses, the
// source's token is given back, so a source does not pay for a budget that
// others spent.
func admitSource(perIP *ipLimiter, global *rate.Limiter, a netip.Addr) (time.Duration, bool) {
	return admitSourceAny(perIP, a, global)
}

// admitSourceAny is admitSource with fallbacks: after the source's bucket,
// the first of globals with a token is charged. The source's token is given
// back only when every one of them refuses.
func admitSourceAny(perIP *ipLimiter, a netip.Addr, globals ...*rate.Limiter) (time.Duration, bool) {
	now := time.Now()
	res, d, ok := perIP.reserve(a, now)
	if !ok {
		return d, false
	}
	wait := time.Duration(0)
	for _, g := range globals {
		_, d, ok := reserveAt(g, now)
		if ok {
			return 0, true
		}
		if wait == 0 || d < wait {
			wait = d
		}
	}
	// CancelAt with the reservation's own time: rate restores tokens only for
	// a reservation that has not yet come due, and with a later time (Cancel
	// uses time.Now) an immediate one never would.
	res.CancelAt(now)
	return wait, false
}

// reserveAt takes a token only if one is available at now, and returns
// its reservation; otherwise it takes nothing and returns the wait (at
// least one second, for Retry-After).
func reserveAt(lim *rate.Limiter, now time.Time) (*rate.Reservation, time.Duration, bool) {
	res := lim.ReserveN(now, 1)
	if !res.OK() {
		return nil, time.Minute, false
	}
	if d := res.DelayFrom(now); d > 0 {
		res.CancelAt(now)
		return nil, max(d, time.Second), false
	}
	return res, 0, true
}

// retryAfter formats a wait as whole seconds, rounded up.
func retryAfter(d time.Duration) string {
	return fmt.Sprint(int64((d + time.Second - 1) / time.Second))
}
