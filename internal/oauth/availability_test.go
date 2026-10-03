package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/time/rate"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
)

// getFrom sends a GET with an X-Forwarded-For header (read only behind a
// trusted proxy).
func getFrom(t *testing.T, c *http.Client, u, xff string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

// unlimitAuthorize lifts the /authorize limiters for tests that send many
// authorization requests on purpose.
func (e *testEnv) unlimitAuthorize() {
	e.svc.authorizeLimit = newIPLimiter(0, 1, ipLimiterSize)
	e.svc.authorizeGlobal = rate.NewLimiter(rate.Inf, 0)
}

// unlimitLogin lifts the per-source login bucket for tests that run many
// ceremonies from one source on purpose (the global bucket stays).
func (e *testEnv) unlimitLogin() {
	e.svc.login.perIP = newIPLimiter(0, 1, ipLimiterSize)
}

func TestAuthorizeRefusesOversizedStateAndNonce(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for name, extra := range map[string]url.Values{
		"state": {"state": {strings.Repeat("s", maxStateBytes+1)}},
		"nonce": {"nonce": {strings.Repeat("n", maxNonceBytes+1)}},
	} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), extra))
		if err != nil {
			t.Fatal(err)
		}
		refusedWithoutRedirect(t, name, resp)
	}
	if n := countRows(t, e.svc.store, "auth_requests"); n != 0 {
		t.Fatalf("%d auth requests stored from refused requests", n)
	}
	// At the limits both are accepted.
	e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{
		"state": {strings.Repeat("s", maxStateBytes)}, "nonce": {strings.Repeat("n", maxNonceBytes)},
	}))
}

// Every /authorize request, valid or not, is charged to its source and then
// to the global bucket, so a flood of requests (each a database row or a
// metadata fetch) is bounded.
func TestAuthorizeIsRateLimitedPerSourceAndGlobally(t *testing.T) {
	e := newTestEnvWith(t, func(o *Options) { o.TrustedProxies = []string{"127.0.0.0/8"} })
	for i := 0; i < authorizePerIPBurst; i++ {
		if resp := getFrom(t, e.browser, e.url+"/authorize", "203.0.113.1"); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("a, request %d: %d", i, resp.StatusCode)
		}
	}
	resp := getFrom(t, e.browser, e.url+"/authorize", "203.0.113.1")
	if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); resp.StatusCode != http.StatusTooManyRequests || err != nil || ra < 1 {
		t.Fatalf("a past its burst: %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Other sources are not blocked by a's bucket, until the global one
	// is spent.
	spent := authorizePerIPBurst
	for src := 2; spent < authorizeGlobalBurst; src++ {
		for i := 0; i < authorizePerIPBurst && spent < authorizeGlobalBurst; i++ {
			if resp := getFrom(t, e.browser, e.url+"/authorize", fmt.Sprintf("203.0.113.%d", src)); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("source %d, request %d: %d", src, i, resp.StatusCode)
			}
			spent++
		}
	}
	if resp := getFrom(t, e.browser, e.url+"/authorize", "198.51.100.7"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a fresh source past the global burst: %d", resp.StatusCode)
	}
	// The refused source paid nothing: its bucket is still full.
	for i := 0; i < authorizePerIPBurst; i++ {
		if _, ok := e.svc.authorizeLimit.allow(netip.MustParseAddr("198.51.100.7")); !ok {
			t.Fatalf("token %d of the globally refused source was not returned", i)
		}
	}
}

// Pending (not yet approved) authorization requests are capped per client
// and globally; the oldest pending ones go first, and an approved one is
// never evicted.
func TestPendingAuthRequestsAreCapped(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "A", loopbackRedirect)
	approved := newApproved(t, o, "A", loopbackRedirect)
	var first string
	for i := 0; i < maxPendingPerClient+5; i++ {
		req, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "A", RedirectURI: loopbackRedirect,
			CodeChallenge: s256("verifier"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = req.GetID()
		}
		clk.Advance(time.Second)
	}
	var pending int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_requests WHERE client_id = 'A' AND done = 0`).Scan(&pending); err != nil || pending != maxPendingPerClient {
		t.Fatalf("pending for one client = %d, %v; want %d", pending, err, maxPendingPerClient)
	}
	if _, err := s.authRequest(first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the oldest pending request survived: %v", err)
	}
	if a, err := s.authRequest(approved.ID); err != nil || !a.IsDone {
		t.Fatalf("the approved request was evicted: %v", err)
	}

	// Globally: many clients, each under its own cap.
	for c := 0; c*maxPendingPerClient < maxPendingAuthRequests+maxPendingPerClient; c++ {
		id := fmt.Sprintf("C%03d", c)
		addClient(t, s, id, loopbackRedirect)
		for i := 0; i < maxPendingPerClient; i++ {
			if _, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: id, RedirectURI: loopbackRedirect,
				CodeChallenge: s256("verifier"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, ""); err != nil {
				t.Fatal(err)
			}
		}
		clk.Advance(time.Second)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_requests WHERE done = 0`).Scan(&pending); err != nil || pending != maxPendingAuthRequests {
		t.Fatalf("pending overall = %d, %v; want %d", pending, err, maxPendingAuthRequests)
	}
	if a, err := s.authRequest(approved.ID); err != nil || !a.IsDone {
		t.Fatalf("the approved request was evicted by the global cap: %v", err)
	}
}

// A cross-site page can make the owner's browser POST to /authorize and
// overwrite the binding cookie; only GET is served.
func TestAuthorizeIsGetOnly(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	q, _ := url.ParseQuery(strings.SplitN(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil), "?", 2)[1])
	resp, err := e.browser.PostForm(e.url+"/authorize", q)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodGet ||
		resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Location") != "" {
		t.Fatalf("POST /authorize: %d, Allow %q, sets a cookie %v", resp.StatusCode, resp.Header.Get("Allow"), resp.Header.Get("Set-Cookie") != "")
	}
	if n := countRows(t, e.svc.store, "auth_requests"); n != 0 {
		t.Fatalf("POST /authorize stored %d requests", n)
	}
}

// The source token is given back when the global bucket refuses: a source
// must not pay for a budget others spent.
func TestGlobalRefusalReturnsTheSourceToken(t *testing.T) {
	s, _ := newTestStore(t)
	l := newLoginPages(s, "http://localhost", discardLogger)
	g := newRegistrar(s, defaultAllowlist(t))
	src := netip.MustParseAddr("203.0.113.9")
	for name, tc := range map[string]struct {
		admit  func(*http.Request) (time.Duration, bool)
		global *rate.Limiter
		perIP  *ipLimiter
		burst  int
	}{
		"login":    {l.admit, l.limit, l.perIP, loginPerIPBurst},
		"register": {g.admit, g.limit, g.perIP, registerPerIPBurst},
	} {
		for tc.global.Allow() {
		}
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = src.String() + ":1234"
		if _, ok := tc.admit(r); ok {
			t.Fatalf("%s: admitted with the global bucket empty", name)
		}
		for i := 0; i < tc.burst; i++ {
			if _, ok := tc.perIP.allow(src); !ok {
				t.Fatalf("%s: source token %d was not returned", name, i)
			}
		}
	}
}

// Passkey ceremonies are charged to the source only: six sources spending
// the global code budget (TOTP guesses) cannot keep the owner from approving
// with a passkey from a seventh.
func TestSourcesDrainingTheCodeBudgetDoNotBlockPasskeys(t *testing.T) {
	e := newTestEnvWith(t, func(o *Options) { o.TrustedProxies = []string{"127.0.0.0/8"} })
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	form := e.pendingLogin(t)
	for src := 1; src <= 6; src++ {
		for i := 0; i < loginPerIPBurst; i++ {
			_, _, _ = postPageFrom(t, e.browser, e.url+"/login", form, fmt.Sprintf("203.0.113.%d", src))
		}
	}
	status, body, resp := postPageFrom(t, e.browser, e.url+"/login", form, "198.51.100.1")
	tooMany(t, "a code from a fresh source after the global budget is spent", status, body, resp)

	id, csrf := e.pendingPasskeyLogin(t, e.register(t, loopbackRedirect))
	hdr := map[string]string{csrfHeader: csrf, "X-Forwarded-For": "198.51.100.7"}
	status, out, _ := postJSONWith(t, e.browser, e.url+"/login/passkey/begin?id="+url.QueryEscape(id), nil, hdr)
	if status != http.StatusOK {
		t.Fatalf("passkey begin from a seventh source: %d %v", status, out["error"])
	}
	assertion := k.get(t, out["publicKey"].(map[string]any)["challenge"].(string), nil)
	status, out, _ = postJSONWith(t, e.browser, e.url+"/login/passkey/finish?id="+url.QueryEscape(id), assertion, hdr)
	if status != http.StatusOK {
		t.Fatalf("passkey finish from a seventh source: %d %v", status, out["error"])
	}
}

// Passkey finish is charged to the source too: one source cannot hammer it.
func TestPasskeyFinishIsChargedToTheSource(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	e.enroll(t, newSoftKey(t, e.url), sec.EnrollToken) // one token of this source
	id, csrf := e.pendingPasskeyLogin(t, e.register(t, loopbackRedirect))
	for i := 1; i < loginPerIPBurst; i++ {
		if status, _ := e.passkeyFinish(t, id, csrf, []byte(`{}`)); status == http.StatusTooManyRequests {
			t.Fatalf("finish %d refused inside the burst", i)
		}
	}
	if status, _ := e.passkeyFinish(t, id, csrf, []byte(`{}`)); status != http.StatusTooManyRequests {
		t.Fatalf("finish past the per-source burst: %d", status)
	}
}

// Requests to /enroll/begin without a live enrollment link are refused
// before any bucket is charged.
func TestJunkEnrollBeginIsFree(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	for i := 0; i < 3*loginPerIPBurst; i++ {
		in, _ := json.Marshal(map[string]string{"token": "forged" + strconv.Itoa(i), "code": "123456"})
		if status, _ := postJSON(t, http.DefaultClient, e.url+"/enroll/begin", in); status != http.StatusBadRequest {
			t.Fatalf("junk enroll begin %d: %d", i, status)
		}
	}
	if got := e.svc.login.limit.Tokens(); got < loginGlobalBurst-0.5 {
		t.Fatalf("junk drew on the global bucket: %.1f tokens left", got)
	}
	for i := 0; i < loginPerIPBurst; i++ {
		if _, ok := e.svc.login.perIP.allow(netip.MustParseAddr("127.0.0.1")); !ok {
			t.Fatalf("junk drew on the source bucket: token %d missing", i)
		}
	}
}

// One source spending its first-fetch budget on metadata document URLs
// leaves the global budget for the others.
func TestCIMDFirstFetchIsLimitedPerSource(t *testing.T) {
	f := &fakeFetch{err: errors.New("unreachable")}
	r, _, _ := newTestResolver(t, f)
	a := withSource(context.Background(), netip.MustParseAddr("203.0.113.1"))
	b := withSource(context.Background(), netip.MustParseAddr("203.0.113.2"))
	for i := 0; i < 3*cimdPerIPBurst; i++ {
		_, _ = r.resolve(a, "https://a"+strconv.Itoa(i)+".example.com/c.json")
	}
	if n := f.calls.Load(); n != cimdPerIPBurst {
		t.Fatalf("one source made %d fetches, want %d", n, cimdPerIPBurst)
	}
	for i := 0; i < cimdPerIPBurst; i++ {
		_, _ = r.resolve(b, "https://b"+strconv.Itoa(i)+".example.com/c.json")
	}
	if n := f.calls.Load(); n != 2*cimdPerIPBurst {
		t.Fatalf("another source was refused: %d fetches in all, want %d", n, 2*cimdPerIPBurst)
	}
}

// Junk codes and refresh tokens are refused with a read: they never wait
// for the write lock, so a flood of them cannot stall real writes (or wait
// behind one).
func TestJunkCodesAndRefreshTokensDoNotTakeTheWriteLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "auth.db")
	db, err := authdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := NewStore(db, nil)
	other, err := authdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	conn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		_ = conn.Close()
	})
	start := time.Now()
	if _, err := s.authRequestByCode("junk-code"); !errors.Is(err, errInvalidCode) {
		t.Fatalf("junk code = %v", err)
	}
	if _, err := s.refreshByToken(refreshPrefix + randToken()); !errors.Is(err, errInvalidRefresh) {
		t.Fatalf("junk refresh token = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("junk lookups waited %v for the write lock", d)
	}
}
