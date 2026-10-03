package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

const (
	cimdMaxBytes     = 64 << 10
	cimdTimeout      = 5 * time.Second
	cimdTTL          = time.Hour
	maxClientIDBytes = 512

	// cimdFailTTL is how long a failed fetch is remembered, so a client (or
	// an attacker) retrying a dead or hostile URL costs one outbound request
	// a minute, not one per attempt.
	cimdFailTTL = time.Minute
	// cimdMaxFailures bounds the in-memory failure cache.
	cimdMaxFailures = 1024
	// cimdMaxStored bounds the CIMD rows kept in the database.
	cimdMaxStored = 1000

	// First-time fetches: a global bucket of 10, refilled every 6 s (10 a
	// minute), and in front of it a bucket per source of cimdPerIPBurst,
	// refilled every cimdPerIPEvery (2 a minute), so one source cannot
	// spend the whole budget and keep new clients of others from connecting.
	cimdGlobalBurst = 10
	cimdGlobalEvery = 6 * time.Second
	cimdPerIPBurst  = 3
	cimdPerIPEvery  = 30 * time.Second
)

// errCIMD is the only error a client sees for a bad document or a failed
// fetch; the details go to the operator log.
var errCIMD = errors.New("client metadata document rejected")

// errCIMDPolicy marks the rejections that mean the host served a
// well-formed document that this server's policy refuses. Only these revoke
// a connected client; garbage bodies are treated like an unreachable host.
var errCIMDPolicy = errors.New("policy")

// isCIMDClientID reports whether a client_id is a metadata document URL
// rather than an id this server issued (DCR ids are base32, never URLs).
func isCIMDClientID(id string) bool { return strings.HasPrefix(id, "https://") }

// checkCIMDURL accepts only https URLs on port 443 with a DNS name and a
// path: no IP literal in any spelling (netip only parses canonical forms, so
// the last label must not look numeric either: the resolver would accept
// 2130706433 or 0x7f.1 as IPv4; the dialer refuses private results anyway),
// no single-label host, no credentials, query, or fragment. Restricting the
// port keeps the fetcher from probing services.
func checkCIMDURL(raw string) error {
	if len(raw) > maxClientIDBytes || strings.ContainsAny(raw, "#\\ ") {
		return errCIMD
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errCIMD
	}
	host := u.Hostname()
	if host == "" || (u.Port() != "" && u.Port() != "443") {
		return errCIMD
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return errCIMD
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(labels) < 2 || numericLabel(labels[len(labels)-1]) {
		return errCIMD
	}
	if u.Path == "" || u.Path == "/" {
		return errCIMD
	}
	return nil
}

// numericLabel reports whether a label is all digits or a 0x hex number, the
// forms legacy resolvers read as an IPv4 component.
func numericLabel(l string) bool {
	if l == "" {
		return true
	}
	if len(l) > 2 && (l[:2] == "0x" || l[:2] == "0X") {
		l = l[2:]
		for _, r := range l {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
		return true
	}
	for _, r := range l {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type cimdDoc struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// parseCIMD validates an untrusted document: client_id must equal the URL it
// was fetched from (the MCP spec requires an exact match), client_name is
// required, the client must be public, and the redirect URIs must pass the
// allowlist.
func parseCIMD(clientID string, body []byte, a allowlist) (clientRow, error) {
	var d cimdDoc
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' {
		return clientRow{}, fmt.Errorf("%w: not a JSON object", errCIMD)
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return clientRow{}, fmt.Errorf("%w: not a JSON object", errCIMD)
	}
	if d.ClientID != clientID {
		return clientRow{}, fmt.Errorf("%w: %w: client_id does not match the document URL", errCIMD, errCIMDPolicy)
	}
	if strings.TrimSpace(d.ClientName) == "" {
		return clientRow{}, fmt.Errorf("%w: client_name is required", errCIMD)
	}
	if m := d.TokenEndpointAuthMethod; m != "" && m != "none" {
		return clientRow{}, fmt.Errorf("%w: %w: only public clients (token_endpoint_auth_method none) are supported", errCIMD, errCIMDPolicy)
	}
	if _, err := a.checkRedirectSet(d.RedirectURIs); err != nil {
		return clientRow{}, fmt.Errorf("%w: %w: %v", errCIMD, errCIMDPolicy, err)
	}
	return clientRow{ID: clientID, Kind: kindCIMD, Name: cleanName(d.ClientName), RedirectURIs: d.RedirectURIs}, nil
}

// blockedPrefixes are non-public ranges netip has no predicate for.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: can map to private IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard
	netip.MustParsePrefix("2001::/32"),       // Teredo: embeds IPv4
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking
	netip.MustParsePrefix("2001:10::/28"),    // deprecated ORCHID
	netip.MustParsePrefix("3fff::/20"),       // documentation
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: embeds IPv4
}

// globalUnicast6 is the only IPv6 space the fetcher may reach. Everything
// else (::/8 IPv4-compatible forms such as ::7f00:1, fec0::/10 site-local,
// the unallocated rest) is refused rather than enumerated.
var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// blockedIP reports whether the fetcher must not connect to ip.
func blockedIP(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.Is6() && !globalUnicast6.Contains(ip) {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDialControl runs on the resolved address of every connection.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("dial %s: not an IP address", host)
	}
	if blockedIP(ip) {
		return fmt.Errorf("dial %s: address not allowed", ip)
	}
	return nil
}

// fetcher downloads client metadata documents: redirects are not followed,
// the body is capped, and the whole request has one deadline.
type fetcher struct{ client *http.Client }

func newFetcher(tr http.RoundTripper, timeout time.Duration) *fetcher {
	return &fetcher{client: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a 3xx is returned as is and rejected below
		},
	}}
}

// newSafeFetcher is the production fetcher. Proxy is nil: an environment
// proxy would make the dialer check the proxy's address, not the target's.
func newSafeFetcher() *fetcher {
	d := &net.Dialer{Timeout: cimdTimeout, Control: safeDialControl}
	return newFetcher(&http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSHandshakeTimeout:    cimdTimeout,
		ResponseHeaderTimeout:  cimdTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
	}, cimdTimeout)
}

func (f *fetcher) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) // #nosec G107 G704 -- the URL passed checkCIMDURL and the dialer refuses non-public addresses
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req) // #nosec G704 -- the URL passed checkCIMDURL and safeDialControl refuses non-public addresses
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch client metadata: status %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, errors.New("fetch client metadata: content type is not application/json")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	if len(body) > cimdMaxBytes {
		return nil, errors.New("fetch client metadata: larger than 64 KiB")
	}
	return body, nil
}

// cimdResolver turns a CIMD client_id into a client row, from the cache
// when it is fresher than cimdTTL, otherwise by fetching the document.
// Successes are cached in the database (so they survive restarts and the
// CLI can list them); failures are cached in memory for cimdFailTTL.
type cimdResolver struct {
	store     *Store
	allow     allowlist
	fetch     func(context.Context, string) ([]byte, error)
	limit     *rate.Limiter // first-time fetches, driven by anonymous /authorize requests
	perIP     *ipLimiter    // per source, in front of limit
	refetch   *rate.Limiter // refreshes of clients we already hold, kept apart so flooding cannot starve them
	logger    *slog.Logger
	maxStored int

	mu          sync.Mutex
	failed      map[string]time.Time // client_id -> when the failure expires
	limitLogged time.Time
	limitHits   int
	staleLogged time.Time
	staleHits   int
}

// cimdStaleMax is how long past its fetch time a connected client's cached
// document is still served when the document host cannot be reached. A
// transient outage (or an attacker exhausting the shared fetch budget) must
// not lock out a client the owner already approved; but a document that was
// fetched and found invalid revokes the client at once, and after a day of
// silence the cache stops vouching for it.
const cimdStaleMax = 24 * time.Hour

// newCIMDResolver limits cache misses to 10 a minute, 2 a minute per source
// after a burst: /authorize is unauthenticated, so without a limit anyone
// could make the server fetch arbitrary public URLs at will.
func newCIMDResolver(store *Store, allow allowlist, fetch func(context.Context, string) ([]byte, error), logger *slog.Logger) *cimdResolver {
	return &cimdResolver{
		store: store, allow: allow, fetch: fetch, logger: logger,
		limit:     rate.NewLimiter(rate.Every(cimdGlobalEvery), cimdGlobalBurst),
		perIP:     newIPLimiter(cimdPerIPEvery, cimdPerIPBurst, ipLimiterSize),
		refetch:   rate.NewLimiter(rate.Every(2*time.Second), 20),
		maxStored: cimdMaxStored,
		failed:    map[string]time.Time{},
	}
}

func (c *cimdResolver) recentlyFailed(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.failed[id]
	if ok && c.store.now().Before(until) {
		return true
	}
	delete(c.failed, id)
	return false
}

func (c *cimdResolver) recordFailure(id string) {
	now := c.store.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.failed) >= cimdMaxFailures {
		for k, until := range c.failed {
			if !now.Before(until) {
				delete(c.failed, k)
			}
		}
	}
	if len(c.failed) >= cimdMaxFailures {
		return // full of live entries: skip caching, the rate limit still applies
	}
	c.failed[id] = now.Add(cimdFailTTL)
}

// makeRoomCIMD evicts the oldest fetched CIMD documents that no grant or pending
// authorization uses, so that inserting one more stays within max rows.
func (s *Store) makeRoomCIMD(id string, max int) error {
	_, err := s.db.Exec(`DELETE FROM oauth_clients WHERE id IN (
			SELECT id FROM oauth_clients
			WHERE kind = 'cimd' AND id != ?1
			  AND NOT EXISTS (SELECT 1 FROM grants WHERE client_id = oauth_clients.id)
			  AND NOT EXISTS (SELECT 1 FROM auth_requests WHERE client_id = oauth_clients.id)
			ORDER BY fetched, id
			LIMIT MAX(0, (SELECT COUNT(*) FROM oauth_clients WHERE kind = 'cimd' AND id != ?1) - ?2 + 1))`, id, max)
	return err
}

// logRateLimited logs at most once a minute, with the number of refusals
// since the last line and never a client id (an attacker chooses them).
func (c *cimdResolver) logRateLimited() {
	now := c.store.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limitHits++
	if now.Sub(c.limitLogged) < time.Minute {
		return
	}
	c.limitLogged = now
	c.logger.Warn("client metadata fetch rate limit reached", "refused", c.limitHits)
	c.limitHits = 0
}

// logServedStale aggregates the stale-serve events like logRateLimited does.
func (c *cimdResolver) logServedStale() {
	now := c.store.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.staleHits++
	if now.Sub(c.staleLogged) < time.Minute {
		return
	}
	c.staleLogged = now
	c.logger.Info("client metadata unavailable, served stale document for connected clients", "count", c.staleHits)
	c.staleHits = 0
}

func (s *Store) hasGrant(id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE client_id = ?`, id).Scan(&n)
	return n > 0, err
}

func (c *cimdResolver) resolve(ctx context.Context, id string) (clientRow, error) {
	row, err := c.store.clientByID(id)
	known := err == nil
	switch {
	case known && row.Kind != kindCIMD:
		return clientRow{}, ErrNotFound
	case known && c.store.now().Sub(row.Fetched) < cimdTTL:
		return row, nil
	case err != nil && !errors.Is(err, ErrNotFound):
		return clientRow{}, err
	}
	if err := checkCIMDURL(id); err != nil {
		return clientRow{}, err
	}
	granted := false
	if known {
		granted, err = c.store.hasGrant(id)
		if err != nil {
			return clientRow{}, err
		}
	}
	// unreachable covers every case where no acceptable document was seen:
	// transport failures, non-200 or wrong content type, rate limiting, and
	// bodies that are not a JSON object. A connected client keeps working
	// from its stale row for cimdStaleMax. Only a well-formed document that
	// policy refuses (client_id mismatch, redirect set not allowed, a
	// non-public auth method) revokes: garbage is something a broken or
	// hijacked host can serve cheaply, and revoking on it would let an
	// outage or an attacker in the path destroy approved connections.
	unreachable := func() (clientRow, error) {
		if granted && c.store.now().Sub(row.Fetched) < cimdStaleMax {
			c.logServedStale()
			return row, nil
		}
		return clientRow{}, errCIMD
	}
	if c.recentlyFailed(id) {
		return unreachable()
	}
	// Only clients with a grant draw on the refetch budget: unconnected
	// rows are as attacker-reachable as new ids and share their limiters
	// (the source's bucket, then the global one; the source is the one
	// Service put in ctx, or a shared bucket when there is none).
	allowed := false
	if granted {
		allowed = c.refetch.Allow()
	} else {
		_, allowed = admitSource(c.perIP, c.limit, sourceFrom(ctx))
	}
	if !allowed {
		c.logRateLimited()
		return unreachable()
	}
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	body, err := c.fetch(ctx, id)
	if err != nil {
		c.logger.Warn("client metadata fetch failed", "client_id", id, "err", err)
		c.recordFailure(id)
		return unreachable()
	}
	fresh, err := parseCIMD(id, body, c.allow)
	if err != nil {
		c.logger.Warn("client metadata document rejected", "client_id", id, "err", err)
		c.recordFailure(id)
		if !errors.Is(err, errCIMDPolicy) {
			return unreachable()
		}
		if known {
			// The host served a document policy refuses: drop the client
			// and every grant it holds.
			if rerr := c.store.RevokeClient(id); rerr != nil && !errors.Is(rerr, ErrNotFound) {
				return clientRow{}, rerr
			}
		}
		return clientRow{}, errCIMD
	}
	now := c.store.now()
	fresh.Created, fresh.Fetched = row.Created, now
	if !known {
		fresh.Created = now
		if err := c.store.makeRoomCIMD(id, c.maxStored); err != nil {
			return clientRow{}, err
		}
	}
	if err := c.store.saveCIMD(fresh); err != nil {
		return clientRow{}, err
	}
	return fresh, nil
}
