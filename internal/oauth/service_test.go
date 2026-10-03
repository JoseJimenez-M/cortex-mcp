package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

const loopbackRedirect = "http://127.0.0.1/callback"

type testEnv struct {
	svc     *Service
	clock   *testClock
	url     string       // the issuer: http://localhost:PORT
	browser *http.Client // a cookie jar that never follows redirects
}

// newTestEnv serves a Service on a real listener. The public URL uses
// "localhost" because WebAuthn refuses IP addresses as relying party ids.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, nil)
}

// newTestEnvWith lets a test change the Options before the Service is built.
func newTestEnvWith(t *testing.T, opts func(*Options)) *testEnv {
	t.Helper()
	var h http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	base := "http://localhost:" + u.Port()
	db, err := authdb.Open(filepath.Join(t.TempDir(), "state", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := newTestClock()
	o := Options{DB: db, PublicURL: base + "/", RedirectAllowlist: config.DefaultRedirectAllowlist(), Logger: discardLogger, Now: clk.Now,
		fetch: (&fakeFetch{err: errors.New("offline")}).fetch}
	if opts != nil {
		opts(&o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.Register(mux)
	h = mux
	e := &testEnv{svc: svc, clock: clk, url: base}
	e.browser = e.newBrowser()
	return e
}

func (e *testEnv) newBrowser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &out)
	return out
}

func (e *testEnv) register(t *testing.T, redirect string) string {
	t.Helper()
	resp, err := http.Post(e.url+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"Test App"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

type pkcePair struct{ verifier, challenge string }

func newPKCE() pkcePair {
	v := rand.Text() + rand.Text()
	return pkcePair{v, s256(v)}
}

func (e *testEnv) authorizeURL(clientID, redirect string, p pkcePair, extra url.Values) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"st-1"},
		"scope": {"vault"}, "code_challenge": {p.challenge}, "code_challenge_method": {"S256"}, "resource": {e.url + "/mcp"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return e.url + "/authorize?" + q.Encode()
}

func locationOf(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	_ = resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Fatalf("status %d, want a redirect", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// startAuthorize follows /authorize to the login redirect and returns the
// auth request id.
func (e *testEnv) startAuthorize(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	loc := locationOf(t, resp)
	if !strings.HasPrefix(loc.String(), e.url+"/login?id=") {
		t.Fatalf("authorize redirected to %s", redacted(loc))
	}
	return loc.Query().Get("id")
}

func (e *testEnv) callback(t *testing.T, c *http.Client, id string) *url.URL {
	t.Helper()
	resp, err := c.Get(e.svc.login.callbackURL(id))
	if err != nil {
		t.Fatal(err)
	}
	return locationOf(t, resp)
}

func (e *testEnv) postForm(t *testing.T, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(e.url+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeJSON(t, resp)
}

func (e *testEnv) exchange(t *testing.T, clientID, code, redirect, verifier string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {clientID},
		"code_verifier": {verifier}, "resource": {e.url + "/mcp"}}
	for k, v := range extra {
		form[k] = v
	}
	return e.postForm(t, "/oauth/token", form)
}

// approvedCode runs a whole authorization with the approval done directly
// in the store (the login page is Task 10) and returns the code.
func (e *testEnv) approvedCode(t *testing.T, clientID string, p pkcePair) string {
	t.Helper()
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, p, nil))
	if err := e.svc.store.completeAuthRequest(id, "otp"); err != nil {
		t.Fatal(err)
	}
	loc := e.callback(t, e.browser, id)
	if loc.Query().Get("iss") != e.url || loc.Query().Get("state") != "st-1" {
		t.Fatalf("callback redirect %s", redacted(loc))
	}
	return loc.Query().Get("code")
}

func TestMetadataDocuments(t *testing.T) {
	e := newTestEnv(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(e.url + p)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s headers = %v", p, resp.Header)
		}
		m := decodeJSON(t, resp)
		if m["resource"] != e.url+"/mcp" || m["authorization_servers"].([]any)[0] != e.url || len(m["scopes_supported"].([]any)) != 1 || m["scopes_supported"].([]any)[0] != "vault" {
			t.Errorf("%s = %v", p, m)
		}
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := http.Get(e.url + p)
		if err != nil {
			t.Fatal(err)
		}
		m := decodeJSON(t, resp)
		want := map[string]any{
			"issuer": e.url, "authorization_endpoint": e.url + "/authorize", "token_endpoint": e.url + "/oauth/token",
			"registration_endpoint": e.url + "/register", "revocation_endpoint": e.url + "/revoke", "jwks_uri": e.url + "/keys",
			"client_id_metadata_document_supported": true, "authorization_response_iss_parameter_supported": true,
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s %s = %v, want %v", p, k, m[k], v)
			}
		}
		for k, v := range map[string]string{
			"code_challenge_methods_supported": "S256", "token_endpoint_auth_methods_supported": "none",
			"response_types_supported": "code", "scopes_supported": "vault offline_access",
			"grant_types_supported": "authorization_code refresh_token", "subject_types_supported": "public",
		} {
			var got []string
			for _, x := range m[k].([]any) {
				got = append(got, x.(string))
			}
			if strings.Join(got, " ") != v {
				t.Errorf("%s %s = %v, want %s", p, k, got, v)
			}
		}
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	p := newPKCE()
	code := e.approvedCode(t, clientID, p)
	status, tok := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, nil)
	if status != http.StatusOK || tok["token_type"] != "Bearer" || tok["scope"] != "vault offline_access" {
		t.Fatalf("token response %d %v", status, tok["error"])
	}
	if exp, _ := tok["expires_in"].(float64); exp < 3500 || exp > 3600 {
		t.Fatalf("expires_in = %v", tok["expires_in"])
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	if !wellFormedRefresh(refresh) || access == "" {
		t.Fatalf("tokens %q %q", access, refresh)
	}
	id, err := e.svc.Verify(context.Background(), access)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.UserID, "oauth:") || id.ClientID != clientID || id.ClientName != "Test App" || id.Scopes[0] != "vault" || !id.Expires.After(e.clock.Now()) {
		t.Fatalf("identity = %+v", id)
	}
	// The code is single use, and replaying it revokes what it issued.
	if status, out := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, nil); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("code replay = %d %v", status, out["error"])
	}
	if _, err := e.svc.Verify(context.Background(), access); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("code replay did not revoke the access token")
	}
}

func TestPKCEMustBeS256(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for name, extra := range map[string]url.Values{
		"plain":   {"code_challenge_method": {"plain"}, "code_challenge": {strings.Repeat("a", 43)}},
		"missing": {"code_challenge_method": {""}, "code_challenge": {""}},
	} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), extra))
		if err != nil {
			t.Fatal(err)
		}
		loc := locationOf(t, resp)
		if !strings.HasPrefix(loc.String(), loopbackRedirect) || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("iss") != e.url || loc.Query().Get("state") != "st-1" {
			t.Errorf("%s: redirected to %s", name, redacted(loc))
		}
	}
}

func TestPKCEVerifierChecked(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	code := e.approvedCode(t, clientID, newPKCE())
	if status, out := e.exchange(t, clientID, code, loopbackRedirect, newPKCE().verifier, nil); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier = %d %v", status, out["error"])
	}
}

func TestResourceIndicator(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for name, res := range map[string][]string{
		"other":  {"https://other.example/mcp"},
		"two":    {e.url + "/mcp", e.url + "/mcp"},
		"origin": {e.url},
		// The resource is compared exactly: no trailing-slash leniency.
		"slash": {e.url + "/mcp/"},
		"empty": {""},
	} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"resource": res}))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d, location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// A missing resource defaults to the MCP URL.
	e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"resource": nil}))

	for _, res := range []string{"https://other.example/mcp", e.url + "/mcp/", e.url} {
		p := newPKCE()
		code := e.approvedCode(t, clientID, p)
		if status, out := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, url.Values{"resource": {res}}); status != http.StatusBadRequest || out["error"] != "invalid_target" {
			t.Fatalf("token with resource %q = %d %v", res, status, out)
		}
	}
	if status, out := e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {clientID},
		"resource": {e.url + "/mcp", e.url + "/mcp"}}); status != http.StatusBadRequest || out["error"] != "invalid_target" {
		t.Fatalf("token with two resources = %d %v", status, out["error"])
	}

	// Without a resource on either request, the token is still bound to
	// the MCP URL and verifies.
	p := newPKCE()
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, p, url.Values{"resource": nil}))
	if err := e.svc.store.completeAuthRequest(id, "otp"); err != nil {
		t.Fatal(err)
	}
	code := e.callback(t, e.browser, id).Query().Get("code")
	status, tok := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, url.Values{"resource": nil})
	if status != http.StatusOK {
		t.Fatalf("exchange without resource = %d %v", status, tok["error"])
	}
	if _, err := e.svc.Verify(context.Background(), tok["access_token"].(string)); err != nil {
		t.Fatalf("token without resource does not verify: %v", err)
	}
	var aud string
	if err := e.svc.store.db.QueryRow(`SELECT audience FROM grants`).Scan(&aud); err != nil || aud != e.url+"/mcp" {
		t.Fatalf("grant audience = %q, %v", aud, err)
	}
}

func TestDefaultScopeAndResponseMode(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"scope": nil}))
	if a, err := e.svc.store.authRequest(id); err != nil || strings.Join(a.Scopes, " ") != "vault offline_access" {
		t.Fatalf("scopes without a scope parameter: %v", err)
	}
	for _, mode := range []string{"fragment", "form_post"} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"response_mode": {mode}}))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("response_mode %s: %d", mode, resp.StatusCode)
		}
	}
}

func TestIssOnLibraryErrorRedirects(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	// prompt=none together with login is an error the library itself
	// redirects (ValidateAuthReqPrompt).
	resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"prompt": {"none login"}}))
	if err != nil {
		t.Fatal(err)
	}
	loc := locationOf(t, resp)
	if loc.Query().Get("error") != "invalid_request" || loc.Query().Get("iss") != e.url || loc.Query().Get("state") != "st-1" {
		t.Fatalf("error redirect %s", redacted(loc))
	}
}

func TestUnknownClientAndRedirectAreNotRedirected(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for name, u := range map[string]string{
		"unknown client": e.authorizeURL("NOPE", loopbackRedirect, newPKCE(), nil),
		"other redirect": e.authorizeURL(clientID, "https://evil.example/cb", newPKCE(), nil),
	} {
		resp, err := e.browser.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestBrowserCookieAndCallbackBinding(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	for _, attr := range []string{browserCookie + "=", "Path=/", "Max-Age=3600", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(sc, attr) {
			t.Errorf("Set-Cookie lacks %s", attr)
		}
	}
	id := locationOf(t, resp).Query().Get("id")
	_ = e.svc.store.completeAuthRequest(id, "otp")
	other := e.newBrowser()
	r2, err := other.Get(e.url + "/authorize/callback?id=" + id)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest || r2.Header.Get("Location") != "" {
		t.Fatalf("callback from another browser: %d %q", r2.StatusCode, r2.Header.Get("Location"))
	}
	if loc := e.callback(t, e.browser, id); loc.Query().Get("code") == "" {
		t.Fatalf("callback from the right browser: %s", redacted(loc))
	}
}

func TestTokenEndpointGuards(t *testing.T) {
	e := newTestEnv(t)
	for _, gt := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:token-exchange", "password", ""} {
		status, out := e.postForm(t, "/oauth/token", url.Values{"grant_type": {gt}, "client_id": {"x"}})
		if status != http.StatusBadRequest || out["error"] != "unsupported_grant_type" {
			t.Errorf("grant %q: %d %v", gt, status, out)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, e.url+"/oauth/token", strings.NewReader("grant_type=refresh_token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token endpoint headers = %v", resp.Header)
	}
}

func TestLibraryOnlyRoutesAreNotMounted(t *testing.T) {
	e := newTestEnv(t)
	for _, p := range []string{"/userinfo", "/oauth/introspect", "/end_session", "/device_authorization", "/ready", "/healthz"} {
		resp, err := http.Get(e.url + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

func TestRefreshAndRevokeOverHTTP(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	p := newPKCE()
	_, tok := e.exchange(t, clientID, e.approvedCode(t, clientID, p), loopbackRedirect, p.verifier, nil)
	r1 := tok["refresh_token"].(string)
	status, tok2 := e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1}, "client_id": {clientID}, "resource": {e.url + "/mcp"}})
	if status != http.StatusOK || tok2["refresh_token"] == r1 || tok2["access_token"] == "" {
		t.Fatalf("refresh = %d %v", status, tok2["error"])
	}
	if status, out := e.postForm(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1}, "client_id": {clientID}}); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", status, out["error"])
	}
	if _, err := e.svc.Verify(context.Background(), tok2["access_token"].(string)); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("reuse did not revoke the family")
	}

	p = newPKCE()
	_, tok = e.exchange(t, clientID, e.approvedCode(t, clientID, p), loopbackRedirect, p.verifier, nil)
	if status, _ := e.postForm(t, "/revoke", url.Values{"token": {tok["access_token"].(string)}, "client_id": {clientID}}); status != http.StatusOK {
		t.Fatalf("revoke: %d", status)
	}
	if _, err := e.svc.Verify(context.Background(), tok["access_token"].(string)); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("revoked access token still verifies")
	}
}

func TestVerifyRejects(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	p := newPKCE()
	_, tok := e.exchange(t, clientID, e.approvedCode(t, clientID, p), loopbackRedirect, p.verifier, nil)
	forged, _ := e.svc.crypto.Encrypt("NOSUCHID:owner")
	for name, token := range map[string]string{
		"empty": "", "garbage": "abc.def", "huge": strings.Repeat("a", 5000), "forged id": forged,
		"refresh token": tok["refresh_token"].(string),
	} {
		if _, err := e.svc.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.clock.Advance(accessTTL)
	if _, err := e.svc.Verify(context.Background(), tok["access_token"].(string)); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("expired access token verifies")
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	db, err := authdb.Open(filepath.Join(t.TempDir(), "s", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := New(Options{DB: db, PublicURL: "https://x.example", RedirectAllowlist: []string{"http://bad/cb"}}); err == nil {
		t.Fatal("bad allowlist accepted")
	}
	if _, err := New(Options{DB: db, PublicURL: "not a url", RedirectAllowlist: []string{"loopback"}}); err == nil {
		t.Fatal("bad public URL accepted")
	}
	if _, err := New(Options{DB: db, PublicURL: "https://x.example", RedirectAllowlist: []string{"loopback"}, TrustedProxies: []string{"0.0.0.0/0"}}); err == nil {
		t.Fatal("trusting every address accepted")
	}
}

// The library accepts any loopback URI whose path matches a native
// client's registration (userinfo, other loopback addresses, https), and
// redirects its own validation errors there. The pre-check must refuse
// these before the library runs, so no error is ever redirected to them.
func TestLooseLoopbackRedirectsAreNeverRedirected(t *testing.T) {
	e := newTestEnv(t)
	e.unlimitAuthorize()
	clientID := e.register(t, loopbackRedirect)
	for _, redirect := range []string{
		"http://evil.com@127.0.0.1/callback",
		"http://127.0.0.2/callback",
		"https://127.0.0.1/callback",
		"http://[::ffff:127.0.0.1]/callback",
		"HTTP://127.0.0.1/callback",
	} {
		for name, extra := range map[string]url.Values{
			"ok":            nil,
			"response_type": {"response_type": {"token"}},
			"scope":         {"scope": {"bogus"}},
			"prompt":        {"prompt": {"none", "login"}},
			"no challenge":  {"code_challenge_method": {""}, "code_challenge": {""}},
		} {
			resp, err := e.browser.Get(e.authorizeURL(clientID, redirect, newPKCE(), extra))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
				t.Errorf("%s with %s: %d %q", redirect, name, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
	}
	// Duplicated client_id or redirect_uri parameters are ambiguous.
	for name, extra := range map[string]url.Values{
		"two redirects": {"redirect_uri": {loopbackRedirect, "http://evil.com@127.0.0.1/callback"}},
		"two clients":   {"client_id": {clientID, clientID}},
		"two modes":     {"response_mode": {"query", "fragment"}},
	} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), extra))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// The registered loopback URI on another port is still accepted (RFC 8252).
	e.startAuthorize(t, e.browser, e.authorizeURL(clientID, "http://127.0.0.1:53682/callback", newPKCE(), nil))
}

func TestIssOnCallbackErrorRedirect(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	// Not approved yet: the library redirects interaction_required.
	loc := e.callback(t, e.browser, id)
	if !strings.HasPrefix(loc.String(), loopbackRedirect) || loc.Query().Get("error") != "interaction_required" || loc.Query().Get("iss") != e.url || loc.Query().Get("state") != "st-1" {
		t.Fatalf("callback error redirect %s", redacted(loc))
	}
}

func TestNoStoreOnRegisterAndToken(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Post(e.url+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+loopbackRedirect+`"],"client_name":"Test App"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	for k, v := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if resp.Header.Get(k) != v {
			t.Errorf("register %s = %q", k, resp.Header.Get(k))
		}
	}
	clientID := out["client_id"].(string)
	p := newPKCE()
	code := e.approvedCode(t, clientID, p)
	resp, err = http.PostForm(e.url+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {loopbackRedirect}, "client_id": {clientID}, "code_verifier": {p.verifier}})
	if err != nil {
		t.Fatal(err)
	}
	tok := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("token: %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("token response headers = %v", resp.Header)
	}
}

// refusedWithoutRedirect asserts a 400 with no Location header.
func refusedWithoutRedirect(t *testing.T, name string, resp *http.Response) {
	t.Helper()
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The library's form decoder matches keys case-insensitively and walks
// the form map in random order, so a case variant of a parameter could
// override the value the pre-check looked at. Each case runs 50 times to
// cover the map orders.
func TestCaseVariantAndRepeatedParametersRefused(t *testing.T) {
	e := newTestEnv(t)
	e.unlimitAuthorize()
	clientID := e.register(t, loopbackRedirect)
	other := e.register(t, "http://localhost/other")
	evil := "http://evil.com@127.0.0.1/callback"
	cases := map[string]func(url.Values){
		"REDIRECT_URI added":    func(q url.Values) { q["REDIRECT_URI"] = []string{evil} },
		"Redirect_Uri only":     func(q url.Values) { q["Redirect_Uri"] = q["redirect_uri"]; delete(q, "redirect_uri") },
		"Client_Id added":       func(q url.Values) { q["Client_Id"] = []string{other} },
		"Response_Mode added":   func(q url.Values) { q["Response_Mode"] = []string{"fragment"} },
		"RESPONSE_TYPE added":   func(q url.Values) { q["RESPONSE_TYPE"] = []string{"token"} },
		"Code_Challenge_Method": func(q url.Values) { q["Code_Challenge_Method"] = []string{"plain"} },
		"Resource added":        func(q url.Values) { q["Resource"] = []string{"https://other.example/mcp"} },
		"two redirect_uri":      func(q url.Values) { q["redirect_uri"] = []string{loopbackRedirect, evil} },
		"two state":             func(q url.Values) { q["state"] = []string{"a", "b"} },
	}
	// U+017F (long s) folds to "s" under strings.EqualFold, as in the decoder.
	cases["long s state"] = func(q url.Values) { q["\u017ftate"] = []string{"x"} }
	for name, mutate := range cases {
		for i := 0; i < 50; i++ {
			q, _ := url.ParseQuery(strings.SplitN(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil), "?", 2)[1])
			mutate(q)
			resp, err := e.browser.Get(e.url + "/authorize?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			refusedWithoutRedirect(t, name, resp)
		}
	}
	// /authorize is GET only (TestAuthorizeIsGetOnly); on the token
	// endpoint a parameter split between the query and the body is a
	// repeat too.
	p := newPKCE()
	code := e.approvedCode(t, clientID, p)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {loopbackRedirect},
		"client_id": {clientID}, "code_verifier": {p.verifier}}
	resp, err := http.PostForm(e.url+"/oauth/token?redirect_uri="+url.QueryEscape(evil), form)
	if err != nil {
		t.Fatal(err)
	}
	if out := decodeJSON(t, resp); resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("token request split between query and body: %d %v", resp.StatusCode, out["error"])
	}
	// Unrelated unknown parameters are dropped, not refused: a request
	// object the library would otherwise act on is simply ignored.
	e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"request": {"x"}, "foo": {"bar"}}))
}

func TestResponseTypeMustBeCode(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for _, rt := range []string{"token", "code id_token", "id_token", "", "CODE"} {
		resp, err := e.browser.Get(e.authorizeURL(clientID, loopbackRedirect, newPKCE(), url.Values{"response_type": {rt}}))
		if err != nil {
			t.Fatal(err)
		}
		refusedWithoutRedirect(t, "response_type "+rt, resp)
	}
}

func TestTokenAndRevokeCaseVariantsRefused(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	for name, extra := range map[string]url.Values{
		"Resource":      {"Resource": {"https://other.example/mcp"}},
		"Code_Verifier": {"Code_Verifier": {newPKCE().verifier}},
		"GRANT_TYPE":    {"GRANT_TYPE": {"client_credentials"}},
		"two codes":     {"code": {"a", "b"}},
	} {
		p := newPKCE()
		code := e.approvedCode(t, clientID, p)
		status, out := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, extra)
		if status != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Errorf("token %s: %d %v", name, status, out["error"])
		}
		// The refused request did not consume the code.
		if status, out := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, nil); status != http.StatusOK {
			t.Errorf("token %s: the code no longer works: %d %v", name, status, out["error"])
		}
	}
	for name, form := range map[string]url.Values{
		"TOKEN":     {"TOKEN": {"x"}, "token": {"y"}, "client_id": {clientID}},
		"Client_Id": {"token": {"x"}, "Client_Id": {clientID}},
	} {
		if status, out := e.postForm(t, "/revoke", form); status != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Errorf("revoke %s: %d %v", name, status, out)
		}
	}
}

func TestIssAppendedWithoutReencoding(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1/cb?b=2&a=1&code=X":        "http://127.0.0.1/cb?b=2&a=1&code=X&iss=https%3A%2F%2Fmcp.example",
		"http://127.0.0.1/cb?z=a+b&iss=old&state=s": "http://127.0.0.1/cb?z=a+b&state=s&iss=https%3A%2F%2Fmcp.example",
		"http://127.0.0.1/cb":                       "http://127.0.0.1/cb?iss=https%3A%2F%2Fmcp.example",
		"https://mcp.example/login?id=1":            "https://mcp.example/login?id=1",
		"/login?id=1":                               "/login?id=1",
	} {
		rec := httptest.NewRecorder()
		w := &issWriter{ResponseWriter: rec, iss: "https://mcp.example"}
		w.Header().Set("Location", in)
		w.WriteHeader(http.StatusFound)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
