package oauth

import (
	"context"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	csrfRE          = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	inlineHandlerRE = regexp.MustCompile(`(?i)\son[a-z]+=`)
)

func (e *testEnv) setupOwner(t *testing.T) SetupSecrets {
	t.Helper()
	sec, err := e.svc.store.Setup("localhost")
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// totpNow returns the code for the current step and moves the clock past
// it, so the next call gets a fresh step (a used step is refused).
func (e *testEnv) totpNow(t *testing.T) string {
	t.Helper()
	code := hotp(ownerSecret(t, e.svc.store), uint64(totpStep(e.clock.Now())), totpDigits)
	defer e.clock.Advance(totpPeriod * time.Second)
	return code
}

func (e *testEnv) loginPage(t *testing.T, c *http.Client, id string) (int, string, http.Header) {
	t.Helper()
	resp, err := c.Get(e.url + "/login?id=" + url.QueryEscape(id))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), resp.Header
}

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF field in:\n%s", body)
	}
	return html.UnescapeString(m[1])
}

func postPage(t *testing.T, c *http.Client, u string, form url.Values) (int, string, *http.Response) {
	t.Helper()
	return postPageFrom(t, c, u, form, "")
}

// postPageFrom posts with an X-Forwarded-For header when xff is set.
func postPageFrom(t *testing.T, c *http.Client, u string, form url.Values, xff string) (int, string, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), resp
}

func (e *testEnv) loginWithTOTP(t *testing.T, c *http.Client, clientID string, p pkcePair) string {
	t.Helper()
	id := e.startAuthorize(t, c, e.authorizeURL(clientID, loopbackRedirect, p, nil))
	status, body, _ := e.loginPage(t, c, id)
	if status != http.StatusOK {
		t.Fatalf("login page: %d %s", status, body)
	}
	status, body, resp := postPage(t, c, e.url+"/login", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {e.totpNow(t)}})
	if status != http.StatusSeeOther || resp.Header.Get("Location") != e.svc.login.callbackURL(id) {
		t.Fatalf("login: %d %q %s", status, resp.Header.Get("Location"), body)
	}
	return e.callback(t, c, id).Query().Get("code")
}

// pageHeadersOK checks the headers every login and message page carries.
func pageHeadersOK(t *testing.T, what string, h http.Header) {
	t.Helper()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "default-src 'none'") ||
		strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") ||
		h.Get("X-Frame-Options") != "DENY" || h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("%s headers = %v", what, h)
	}
}

func TestLoginWithTOTP(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	status, body, h := e.loginPage(t, e.browser, id)
	if status != http.StatusOK || !strings.Contains(body, "Test App") || !strings.Contains(body, "127.0.0.1") || strings.Contains(body, "Approve with passkey") {
		t.Fatalf("login page: %d\n%s", status, body)
	}
	pageHeadersOK(t, "login page", h)
	if !strings.Contains(h.Get("Content-Security-Policy"), "form-action 'self' http://127.0.0.1") {
		t.Fatalf("form-action: %v", h)
	}
	// No passkey yet: no script at all, and never an inline handler.
	if strings.Contains(body, "<script") || inlineHandlerRE.MatchString(body) {
		t.Fatalf("script or inline handler on the page:\n%s", body)
	}
	p := newPKCE()
	code := e.loginWithTOTP(t, e.browser, clientID, p)
	if status, tok := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, nil); status != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("exchange after login: %d %v", status, tok["error"])
	}
}

func TestMessagePagesCarryTheSameHeaders(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	status, _, h := e.loginPage(t, e.browser, "nope")
	if status != http.StatusBadRequest {
		t.Fatalf("unknown id: %d", status)
	}
	pageHeadersOK(t, "message page", h)
}

func TestLoginWithRecoveryCode(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	status, _, _ := postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {strings.ToLower(sec.RecoveryCodes[0])}})
	if status != http.StatusSeeOther {
		t.Fatalf("recovery login: %d", status)
	}
	if n, _ := e.svc.store.recoveryCodesLeft(); n != 9 {
		t.Fatalf("%d recovery codes left", n)
	}
}

func TestWrongCodeKeepsTheRequestPending(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	csrf := csrfOf(t, body)
	wrong := wrongTOTP(ownerSecret(t, e.svc.store), e.clock.Now())
	status, body, _ := postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrf}, "code": {wrong}})
	if status != http.StatusUnauthorized || !strings.Contains(body, "Code not accepted") || !strings.Contains(body, csrf) {
		t.Fatalf("wrong code: %d %s", status, body)
	}
	if status, _, _ := postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrf}, "code": {e.totpNow(t)}}); status != http.StatusSeeOther {
		t.Fatalf("right code after a wrong one: %d", status)
	}
}

func TestLoginNeedsTheSameBrowserAndCSRF(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	csrf := csrfOf(t, body)
	other := e.newBrowser()
	if status, _, _ := e.loginPage(t, other, id); status != http.StatusBadRequest {
		t.Fatalf("login page in another browser: %d", status)
	}
	for name, tc := range map[string]struct {
		c    *http.Client
		path string
		form url.Values
	}{
		"other browser":       {other, "/login", url.Values{"id": {id}, "csrf": {csrf}, "code": {"123456"}}},
		"wrong csrf":          {e.browser, "/login", url.Values{"id": {id}, "csrf": {"AAAAAAAAAAAAAAAAAAAAAAAAAA"}, "code": {"123456"}}},
		"no csrf":             {e.browser, "/login", url.Values{"id": {id}, "code": {"123456"}}},
		"no id":               {e.browser, "/login", url.Values{"csrf": {csrf}, "code": {"123456"}}},
		"deny, wrong csrf":    {e.browser, "/login/deny", url.Values{"id": {id}, "csrf": {"AAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
		"deny, other browser": {other, "/login/deny", url.Values{"id": {id}, "csrf": {csrf}}},
	} {
		if status, _, _ := postPage(t, tc.c, e.url+tc.path, tc.form); status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
	}
	var fails int
	if err := e.svc.store.db.QueryRow(`SELECT totp_failures FROM owner`).Scan(&fails); err != nil || fails != 0 {
		t.Fatalf("refused requests reached the code check: failures %d, %v", fails, err)
	}
	if _, err := e.svc.store.authRequest(id); err != nil {
		t.Fatalf("a refused deny dropped the request: %v", err)
	}
}

// pendingLogin starts an authorization and returns the login form fields
// with a wrong TOTP code.
func (e *testEnv) pendingLogin(t *testing.T) url.Values {
	t.Helper()
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	return url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {wrongTOTP(ownerSecret(t, e.svc.store), e.clock.Now())}}
}

func tooMany(t *testing.T, what string, status int, body string, resp *http.Response) {
	t.Helper()
	if status != http.StatusTooManyRequests || !strings.Contains(body, "Too many attempts") || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("%s: %d %s", what, status, body)
	}
}

// One source gets loginPerIPBurst attempts. Without trusted proxies the
// X-Forwarded-For header is ignored, so rotating it buys nothing.
func TestLoginIsRateLimitedPerSource(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	form := e.pendingLogin(t)
	for i := 0; i < loginPerIPBurst; i++ {
		if status, _, _ := postPageFrom(t, e.browser, e.url+"/login", form, fmt.Sprintf("198.51.100.%d", i+1)); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, status)
		}
	}
	status, body, resp := postPageFrom(t, e.browser, e.url+"/login", form, "198.51.100.200")
	tooMany(t, "attempt past the per-source burst with a spoofed X-Forwarded-For", status, body, resp)
}

// Behind a trusted proxy each client address has its own bucket, and the
// global limiter still caps all of them together.
func TestLoginRateLimitPerSourceBehindTrustedProxy(t *testing.T) {
	e := newTestEnvWith(t, func(o *Options) { o.TrustedProxies = []string{"127.0.0.0/8"} })
	e.setupOwner(t)
	form := e.pendingLogin(t)
	post := func(ip string) (int, string, *http.Response) {
		return postPageFrom(t, e.browser, e.url+"/login", form, ip)
	}
	for i := 0; i < loginPerIPBurst; i++ {
		if status, _, _ := post("203.0.113.1"); status != http.StatusUnauthorized {
			t.Fatalf("a, attempt %d: %d", i, status)
		}
	}
	status, body, resp := post("203.0.113.1")
	tooMany(t, "a past its burst", status, body, resp)
	// b is not blocked by a's exhausted bucket.
	for i := 0; i < loginGlobalBurst-loginPerIPBurst; i++ {
		if status, _, _ := post("203.0.113.2"); status != http.StatusUnauthorized {
			t.Fatalf("b, attempt %d: %d", i, status)
		}
	}
	// The global bucket is now empty: a third source is refused too.
	status, body, resp = post("203.0.113.3")
	tooMany(t, "c after the global burst", status, body, resp)
}

func TestLockedTOTPIsExplained(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	if _, err := e.svc.store.db.Exec(`UPDATE owner SET totp_failures = ?`, maxTOTPFailures); err != nil {
		t.Fatal(err)
	}
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	status, body, _ := postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {e.totpNow(t)}})
	if status != http.StatusUnauthorized || !strings.Contains(body, "locked") {
		t.Fatalf("locked TOTP: %d %s", status, body)
	}
}

// recordHandler keeps every log record, for tests that check what was logged.
type recordHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

// text renders every record with its attributes, one per line.
func (h *recordHandler) text() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.recs {
		s := r.Level.String() + " " + r.Message
		r.Attrs(func(a slog.Attr) bool { s += " " + a.String(); return true })
		out = append(out, s)
	}
	return out
}

// The failure that trips the TOTP lock logs one warning; later refusals do
// not repeat it. No code appears in any log line.
func TestTOTPLockWarnsOnce(t *testing.T) {
	logs := &recordHandler{}
	e := newTestEnvWith(t, func(o *Options) { o.Logger = slog.New(logs) })
	e.setupOwner(t)
	if _, err := e.svc.store.db.Exec(`UPDATE owner SET totp_failures = ?`, maxTOTPFailures-1); err != nil {
		t.Fatal(err)
	}
	form := e.pendingLogin(t)
	wrong := form.Get("code")
	status, body, _ := postPage(t, e.browser, e.url+"/login", form)
	if status != http.StatusUnauthorized || !strings.Contains(body, "locked") {
		t.Fatalf("tripping failure: %d %s", status, body)
	}
	good := e.totpNow(t)
	form.Set("code", good)
	if status, body, _ := postPage(t, e.browser, e.url+"/login", form); status != http.StatusUnauthorized || !strings.Contains(body, "locked") {
		t.Fatalf("after the lock: %d %s", status, body)
	}
	warns := 0
	for _, l := range logs.text() {
		if strings.HasPrefix(l, "WARN") && strings.Contains(l, "locked") {
			warns++
		}
		if strings.Contains(l, wrong) || strings.Contains(l, good) {
			t.Fatalf("a code reached the log: %s", l)
		}
	}
	if warns != 1 {
		t.Fatalf("%d lock warnings, want 1: %q", warns, logs.text())
	}
}

func TestLoginBeforeSetup(t *testing.T) {
	e := newTestEnv(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	status, body, _ := e.loginPage(t, e.browser, id)
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "cortex-mcp setup") {
		t.Fatalf("before setup: %d %s", status, body)
	}
}

func TestDenyRedirectsWithAccessDenied(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	status, _, resp := postPage(t, e.browser, e.url+"/login/deny", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if status != http.StatusSeeOther || !strings.HasPrefix(loc.String(), loopbackRedirect+"?") || loc.Query().Get("error") != "access_denied" ||
		loc.Query().Get("state") != "st-1" || loc.Query().Get("iss") != e.url {
		t.Fatalf("deny: %d %s", status, loc)
	}
	r2, err := e.browser.Get(e.url + "/authorize/callback?id=" + id)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback after deny: %d", r2.StatusCode)
	}
}

func TestApprovedOrExpiredRequestsAreClosed(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	_, _, _ = postPage(t, e.browser, e.url+"/login", url.Values{"id": {id}, "csrf": {csrfOf(t, body)}, "code": {e.totpNow(t)}})
	if status, _, _ := e.loginPage(t, e.browser, id); status != http.StatusBadRequest {
		t.Fatalf("login page after approval: %d", status)
	}
	id2 := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	e.clock.Advance(authRequestTTL)
	if status, _, _ := e.loginPage(t, e.browser, id2); status != http.StatusBadRequest {
		t.Fatalf("login page after expiry: %d", status)
	}
}

func TestLoginPageEscapesClientNames(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	resp, err := http.Post(e.url+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+loopbackRedirect+`"],"client_name":"<script>alert(1)</script><img src=x onerror=alert(2)>"}`))
	if err != nil {
		t.Fatal(err)
	}
	clientID := decodeJSON(t, resp)["client_id"].(string)
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("client name not escaped:\n%s", body)
	}
}

// The hosts the owner can verify (where the browser returns, and who
// published a client metadata document) are shown as prominently as the
// name, which the client chose itself.
func TestConsentShowsHostsAsProminentlyAsTheName(t *testing.T) {
	e := newTestEnv(t)
	e.setupOwner(t)
	const cimdID = "https://app.example.com/oauth/client.json"
	if err := e.svc.store.insertClient(clientRow{ID: cimdID, Kind: kindCIMD, Name: "Claude", RedirectURIs: []string{loopbackRedirect},
		Created: e.clock.Now(), Fetched: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	id := e.startAuthorize(t, e.browser, e.authorizeURL(cimdID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	for _, want := range []string{"<strong>Claude</strong>", "<strong>127.0.0.1</strong>", "<strong>app.example.com</strong>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q:\n%s", want, body)
		}
	}
	// A DCR client has no publisher host to show.
	dcr := e.register(t, loopbackRedirect)
	id = e.startAuthorize(t, e.browser, e.authorizeURL(dcr, loopbackRedirect, newPKCE(), nil))
	_, body, _ = e.loginPage(t, e.browser, id)
	if strings.Contains(body, "Published by") || !strings.Contains(body, "<strong>127.0.0.1</strong>") {
		t.Fatalf("dcr consent:\n%s", body)
	}
}
