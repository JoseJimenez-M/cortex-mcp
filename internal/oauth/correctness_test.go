package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// An unknown or revoked client is the client's problem (invalid_client),
// not a server error: the library maps a plain error to 500.
func TestUnknownClientIsInvalidClient(t *testing.T) {
	o, _, _ := newTestOP(t)
	_, err1 := o.GetClientByClientID(context.Background(), "NOPE")
	_, err2 := o.GetClientByClientID(context.Background(), "NOPE")
	var e1, e2 *oidc.Error
	if !errors.As(err1, &e1) || !errors.As(err2, &e2) || e1.ErrorType != oidc.InvalidClient || e1.Description != "client not found" {
		t.Fatalf("unknown client error = %v", err1)
	}
	if e1 == e2 {
		t.Fatal("the error value is shared between calls; the library mutates it")
	}
}

func TestRefreshByRevokedClientIsInvalidClient(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	p := newPKCE()
	_, tok := e.exchange(t, clientID, e.approvedCode(t, clientID, p), loopbackRedirect, p.verifier, nil)
	refresh, _ := tok["refresh_token"].(string)
	if err := e.svc.store.RevokeClient(clientID); err != nil {
		t.Fatal(err)
	}
	status, out := e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	if status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Fatalf("refresh by a revoked client: %d %v", status, out["error"])
	}
}

// A metadata document may list redirect URIs this server does not allow:
// they are dropped, and the client keeps the ones that are allowed.
func TestCIMDKeepsOnlyAllowedRedirects(t *testing.T) {
	a := defaultAllowlist(t)
	row, err := parseCIMD(testCIMD, cimdBody(testCIMD, "A", "https://evil.example/cb", "http://127.0.0.1/cb"), a)
	if err != nil || len(row.RedirectURIs) != 1 || row.RedirectURIs[0] != "http://127.0.0.1/cb" {
		t.Fatalf("parseCIMD = %+v, %v", row, err)
	}
	// A connected client whose document gains an extra redirect keeps
	// working.
	r, f, s, _ := grantedResolver(t)
	f.body.Store(cimdBody(testCIMD, "New", "http://127.0.0.1/cb", "https://evil.example/cb"))
	if row, err := r.resolve(context.Background(), testCIMD); err != nil || row.Name != "New" || len(row.RedirectURIs) != 1 {
		t.Fatalf("refetch with an extra redirect = %+v, %v", row, err)
	}
	if n := countRows(t, s, "grants"); n != 1 {
		t.Fatalf("the client lost its grant: %d grants", n)
	}
}

// The token endpoint sweeps too (every connected client keeps using it),
// at most every tokenSweepEvery.
func TestTokenEndpointSweeps(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	tokenCall := func() {
		_, _ = e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {clientID}})
	}
	e.clock.Advance(authRequestTTL + time.Second)
	e.svc.store.lastSweep.Store(e.clock.Now().Unix()) // a sweep ran just before the request expired
	e.clock.Advance(tokenSweepEvery - time.Second)
	tokenCall()
	if n := countRows(t, e.svc.store, "auth_requests"); n != 1 {
		t.Fatalf("swept within tokenSweepEvery of the last sweep: %d auth requests left", n)
	}
	e.clock.Advance(time.Second)
	tokenCall()
	if n := countRows(t, e.svc.store, "auth_requests"); n != 0 {
		t.Fatalf("the token endpoint did not sweep: %d expired auth requests left", n)
	}
}

func TestSweepErrorsAreLoggedAtWarn(t *testing.T) {
	logs := &recordHandler{}
	e := newTestEnvWith(t, func(o *Options) { o.Logger = slog.New(logs) })
	e.setupOwner(t) // leaves an enrollment link
	if _, err := e.svc.store.db.Exec(`CREATE TRIGGER fail_sweep BEFORE DELETE ON enrollments BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour)
	_, _ = e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"x"}})
	for _, l := range logs.text() {
		if strings.HasPrefix(l, "WARN") && strings.Contains(l, "sweep") {
			return
		}
	}
	t.Fatalf("no sweep warning: %q", logs.text())
}

// A used code is kept until authRequestTTL, beyond its own lifetime, so a
// replay that comes late still revokes what the first use issued.
func TestLateCodeReplayStillRevokesTheFamily(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "A", "http://127.0.0.1/callback")
	exchange := func() (string, *authRequest) {
		a := newApproved(t, o, "A", "http://127.0.0.1/callback")
		code := rand.Text()
		if err := o.SaveAuthCode(context.Background(), a.ID, code); err != nil {
			t.Fatal(err)
		}
		got, err := o.AuthRequestByCode(context.Background(), code)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), got, ""); err != nil {
			t.Fatal(err)
		}
		return code, a
	}
	replayed, a := exchange()
	_, b := exchange()
	clk.Advance(codeTTL + 2*sweepEvery)
	if err := s.sweepAfter(0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.AuthRequestByCode(context.Background(), replayed); err == nil {
		t.Fatal("a replayed code was accepted")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants WHERE family = ?`, a.Family); n != 0 {
		t.Fatal("a late replay left its family alive")
	}
	// The other used code is still kept, and goes once authRequestTTL
	// has passed since it was issued.
	const q = `SELECT COUNT(*) FROM auth_codes WHERE family = ?`
	if n := count(t, s, q, b.Family); n != 1 {
		t.Fatal("a used code was swept before authRequestTTL")
	}
	clk.Advance(authRequestTTL - codeTTL - 2*sweepEvery)
	if err := s.sweepAfter(0); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, q, b.Family); n != 0 {
		t.Fatal("a used code was kept past authRequestTTL")
	}
}

// Logs carry only the host of a client metadata document URL: the rest is
// chosen by whoever sends the request.
func TestCIMDLogsCarryOnlyTheHost(t *testing.T) {
	logs := &recordHandler{}
	s, _ := newTestStore(t)
	id := "https://app.example.com/attacker-chosen-path.json"
	fetchErr := &url.Error{Op: "Get", URL: id, Err: errors.New("connection refused")}
	r := newCIMDResolver(s, defaultAllowlist(t), func(context.Context, string) ([]byte, error) { return nil, fetchErr }, slog.New(logs))
	_, _ = r.resolve(context.Background(), id)
	r2 := newCIMDResolver(s, defaultAllowlist(t), func(context.Context, string) ([]byte, error) {
		return cimdBody("https://other.example.com/attacker-chosen-path.json", "A", "http://127.0.0.1/cb"), nil
	}, slog.New(logs))
	_, _ = r2.resolve(context.Background(), id)
	text := strings.Join(logs.text(), "\n")
	if len(logs.text()) < 2 || strings.Contains(text, "attacker-chosen") || !strings.Contains(text, "app.example.com") {
		t.Fatalf("log = %q", text)
	}
	if got := logClientID("https://" + strings.Repeat("a", 300) + ".example.com/x"); len(got) > 253 {
		t.Fatalf("logged host is %d bytes", len(got))
	}
	if got := logClientID("MFRGGZDFMZTWQ2LK"); got != "MFRGGZDFMZTWQ2LK" {
		t.Fatalf("a DCR id is logged as %q", got)
	}
}

// The login page names a CIMD client by its URL in the logs only by host.
func TestLoginLogsCarryOnlyTheCIMDHost(t *testing.T) {
	logs := &recordHandler{}
	e := newTestEnvWith(t, func(o *Options) { o.Logger = slog.New(logs) })
	e.setupOwner(t)
	if err := e.svc.store.saveCIMD(clientRow{ID: testCIMD, Kind: kindCIMD, Name: "Doc", RedirectURIs: []string{loopbackRedirect},
		Created: e.clock.Now(), Fetched: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	id := e.startAuthorize(t, e.browser, e.authorizeURL(testCIMD, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	_, _, _ = postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {wrongTOTP(ownerSecret(t, e.svc.store), e.clock.Now())}})
	text := strings.Join(logs.text(), "\n")
	if !strings.Contains(text, "login failed") || strings.Contains(text, "/oauth/client.json") {
		t.Fatalf("log = %q", text)
	}
}

// A loopback IPv6 redirect cannot be named in a CSP source list (the
// grammar has no IPv6 literals; browsers drop the source), so the login
// page allows the scheme instead, and other hosts keep their origin.
func TestFormActionForIPv6LoopbackRedirects(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	for redirect, want := range map[string]string{
		"http://[::1]:8976/callback": "form-action 'self' http:;",
		loopbackRedirect:             "form-action 'self' http://127.0.0.1;",
		"http://localhost/cb":        "form-action 'self' http://localhost;",
	} {
		clientID := e.register(t, redirect)
		id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, redirect, newPKCE(), nil))
		_, _, h := e.loginPage(t, e.browser, id)
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, want) {
			t.Errorf("%s: CSP %q, want %q", redirect, csp, want)
		}
	}
}

// Every redirect to a client, success or error, carries exactly one iss
// (RFC 9207): a client that checks iss must never see none or two.
func TestEveryClientRedirectCarriesExactlyOneIss(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	var locs []*url.URL
	get := func(u string) *url.URL {
		resp, err := e.browser.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		return locationOf(t, resp)
	}
	// Success.
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	if err := e.svc.store.completeAuthRequest(id, "otp"); err != nil {
		t.Fatal(err)
	}
	locs = append(locs, e.callback(t, e.browser, id))
	// Errors from the library, from our PKCE check, and from the callback.
	locs = append(locs, get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"prompt": {"none login"}})))
	locs = append(locs, get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"code_challenge_method": {"plain"}})))
	pending := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	locs = append(locs, e.callback(t, e.browser, pending))
	// The owner's denial.
	denied := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, denied)
	_, _, resp := postPage(t, e.browser, e.url+"/login/deny", url.Values{"id": {denied}, "csrf": {csrfOf(t, body)}})
	locs = append(locs, locationOf(t, resp))
	for i, loc := range locs {
		if !strings.HasPrefix(loc.String(), loopbackRedirect) || len(loc.Query()["iss"]) != 1 || loc.Query().Get("iss") != e.url {
			t.Errorf("redirect %d: %s", i, redacted(loc))
		}
	}
}
