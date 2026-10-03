package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 test helper
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/oauth"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

const e2eRedirect = "http://127.0.0.1/callback"

type oauthEnv struct {
	url      string // http://localhost:PORT, the issuer
	svc      *oauth.Service
	db       *sql.DB
	tokens   *tokens.Store
	bearer   string // a Bearer token named "cli"
	stateDir string
	totp     []byte   // the owner's TOTP secret
	recovery []string // the owner's recovery codes
	clock    *clock
	seen     *secretSet // when set, the helpers record every secret they handle
}

// secretSet collects the secrets a flow handled, so a test can check that
// none of them reached a log. The helpers may run on SDK goroutines.
type secretSet struct {
	mu sync.Mutex
	v  []string
}

func (s *secretSet) add(v ...string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range v {
		if x != "" {
			s.v = append(s.v, x)
		}
	}
}

func (s *secretSet) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.v)
}

// setupOAuth serves the whole server with OAuth enabled and the owner set
// up. The clock starts at the real time: the OAuth library and the SDK
// compare token expiry with time.Now.
func setupOAuth(t *testing.T, mutate func(*config.Config)) oauthEnv {
	t.Helper()
	return setupOAuthLogging(t, mutate, io.Discard)
}

// setupOAuthLogging is setupOAuth with the server's and the OAuth service's
// operator logs written, at debug level, to out.
func setupOAuthLogging(t *testing.T, mutate func(*config.Config), out io.Writer) oauthEnv {
	t.Helper()
	vaultDir, stateDir := t.TempDir(), t.TempDir()
	var h http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	u, _ := url.Parse(ts.URL)
	cfg := config.Default()
	cfg.Vault, cfg.StateDir, cfg.PublicURL = vaultDir, stateDir, "http://localhost:"+u.Port()
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := vault.New(vaultDir, vault.Options{MaxWriteBytes: cfg.Limits.MaxWriteBytes})
	if err != nil {
		t.Fatal(err)
	}
	db, err := authdb.Open(filepath.Join(stateDir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := tokens.New(db)
	secret, err := store.Create("cli")
	if err != nil {
		t.Fatal(err)
	}
	lg, err := logs.Open(stateDir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{}
	clk.ns.Store(time.Now().UnixNano())
	quiet := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc, err := oauth.New(oauth.Options{DB: db, PublicURL: cfg.PublicURL, RedirectAllowlist: cfg.OAuth.RedirectAllowlist, Logger: quiet, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := svc.Store().Setup("localhost")
	if err != nil {
		t.Fatal(err)
	}
	su, _ := url.Parse(sec.TOTPURI)
	totp, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(su.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	h = New(Options{Config: cfg, Vault: v, Tokens: store, Log: lg, Now: clk.Now, Logger: quiet, OAuth: svc})
	t.Cleanup(func() {
		ts.Close()
		_ = lg.Close()
		_ = db.Close()
		_ = v.Close()
	})
	return oauthEnv{url: cfg.PublicURL, svc: svc, db: db, tokens: store, bearer: secret, stateDir: stateDir, totp: totp, recovery: sec.RecoveryCodes, clock: clk}
}

// totpCode is RFC 6238 (HMAC-SHA1, 30 s, 6 digits), written out here so
// the test does not trust the code under test to compute it.
func totpCode(secret []byte, now time.Time) string {
	mac := hmac.New(sha1.New, secret) // #nosec G401 -- RFC 6238
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/30))
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// browserAuthorize plays the owner's browser: /authorize, the login page
// with a fresh TOTP code, the callback. It returns the query of the final
// redirect to the client. It returns errors instead of failing the test
// because the SDK may call it from a goroutine other than the test's.
func (e oauthEnv) browserAuthorize(authURL string) (url.Values, error) {
	return e.browserAuthorizeWith(authURL, func() string {
		e.clock.Advance(30 * time.Second) // a fresh TOTP step for every login
		return totpCode(e.totp, e.clock.Now())
	})
}

// browserAuthorizeWith is browserAuthorize with the login factor (a TOTP
// code or a recovery code) supplied by factor.
func (e oauthEnv) browserAuthorizeWith(authURL string, factor func() string) (url.Values, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := func(resp *http.Response, err error, want int) (*url.URL, string, error) {
		if err != nil {
			return nil, "", err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			return nil, "", fmt.Errorf("status %d, want %d: %s", resp.StatusCode, want, body)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		return loc, string(body), err
	}
	resp, err := c.Get(authURL)
	login, _, err := next(resp, err, http.StatusFound)
	if err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	resp, err = c.Get(login.String())
	_, page, err := next(resp, err, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("login page: %w", err)
	}
	m := csrfField.FindStringSubmatch(page)
	if m == nil {
		return nil, errors.New("login page has no CSRF field")
	}
	code := factor()
	e.seen.add(code)
	resp, err = c.PostForm(e.url+"/login", url.Values{"id": {login.Query().Get("id")}, "csrf": {m[1]}, "code": {code}})
	cb, _, err := next(resp, err, http.StatusSeeOther)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	resp, err = c.Get(cb.String())
	final, _, err := next(resp, err, http.StatusFound)
	if err != nil {
		return nil, fmt.Errorf("callback: %w", err)
	}
	if u, err := url.Parse(e.url); err == nil {
		for _, ck := range jar.Cookies(u) {
			e.seen.add(ck.Value)
		}
	}
	e.seen.add(final.Query().Get("code"))
	return final.Query(), nil
}

func (e oauthEnv) registerClient(t *testing.T) string {
	t.Helper()
	resp, err := http.Post(e.url+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+e2eRedirect+`"],"client_name":"scripted"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v %v", resp.StatusCode, out, err)
	}
	return out["client_id"].(string)
}

func (e oauthEnv) tokenRequest(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(e.url+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// grant runs a scripted authorization code flow with PKCE and resource.
func (e oauthEnv) grant(t *testing.T, clientID string) (string, string) {
	t.Helper()
	verifier := rand.Text() + rand.Text()
	e.seen.add(verifier)
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {e2eRedirect}, "state": {"s"},
		"scope": {"vault"}, "code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}, "resource": {e.url + "/mcp"}}
	res, err := e.browserAuthorize(e.url + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if res.Get("iss") != e.url || res.Get("state") != "s" {
		t.Fatalf("authorization response %v", res)
	}
	status, tok := e.tokenRequest(t, url.Values{"grant_type": {"authorization_code"}, "code": {res.Get("code")}, "redirect_uri": {e2eRedirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {e.url + "/mcp"}})
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	e.seen.add(tok["access_token"].(string), tok["refresh_token"].(string))
	return tok["access_token"].(string), tok["refresh_token"].(string)
}

func (e oauthEnv) refresh(t *testing.T, clientID, refresh string) (int, map[string]any) {
	t.Helper()
	status, out := e.tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "resource": {e.url + "/mcp"}})
	for _, k := range []string{"access_token", "refresh_token"} {
		if v, ok := out[k].(string); ok {
			e.seen.add(v)
		}
	}
	return status, out
}

func challengeOf(t *testing.T, base, auth string) (int, string) {
	t.Helper()
	resp := doPost(t, base, auth, pingBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

func TestUnauthenticatedMCPPointsToOAuthMetadata(t *testing.T) {
	e := setupOAuth(t, nil)
	want := `Bearer resource_metadata="` + e.url + `/.well-known/oauth-protected-resource/mcp", scope="vault"`
	for _, auth := range []string{"", "Bearer nope", "Bearer cmcp_" + strings.Repeat("A", 43)} {
		if status, h := challengeOf(t, e.url, auth); status != http.StatusUnauthorized || h != want {
			t.Errorf("auth %q: %d %q", auth, status, h)
		}
	}
	resp, err := http.Get(e.url + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PRM: %d", resp.StatusCode)
	}
}

func TestOAuthAndBearerTokensBothWork(t *testing.T) {
	e := setupOAuth(t, nil)
	access, _ := e.grant(t, e.registerClient(t))
	for name, tok := range map[string]string{"oauth": access, "bearer": e.bearer} {
		if code := post(t, e.url, "Bearer "+tok); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("%s token: %d", name, code)
		}
	}
	id, err := e.svc.Verify(t.Context(), access)
	if err != nil || !strings.HasPrefix(id.UserID, "oauth:") || id.ClientName != "scripted" {
		t.Fatalf("identity %+v, %v", id, err)
	}
}

func TestBearerTokensCanBeTurnedOff(t *testing.T) {
	e := setupOAuth(t, func(c *config.Config) { c.BearerTokens = false })
	if code := post(t, e.url, "Bearer "+e.bearer); code != http.StatusUnauthorized {
		t.Fatalf("bearer token with bearer_tokens false: %d", code)
	}
	access, _ := e.grant(t, e.registerClient(t))
	if code := post(t, e.url, "Bearer "+access); code == http.StatusUnauthorized {
		t.Fatal("OAuth token refused")
	}
}

func TestTokenWithoutVaultScopeIsForbidden(t *testing.T) {
	e := setupOAuth(t, nil)
	access, _ := e.grant(t, e.registerClient(t))
	if _, err := e.db.Exec(`UPDATE access_tokens SET scopes = 'offline_access'`); err != nil {
		t.Fatal(err)
	}
	if status, h := challengeOf(t, e.url, "Bearer "+access); status != http.StatusForbidden || !strings.Contains(h, `scope="vault"`) {
		t.Fatalf("token without vault: %d %q", status, h)
	}
}

func TestOAuthDisabledKeepsThePlan1Surface(t *testing.T) {
	e := setup(t, nil) // Options.OAuth is nil
	if status, h := challengeOf(t, e.url, ""); status != http.StatusUnauthorized || h != "" {
		t.Fatalf("401 without OAuth: %d %q", status, h)
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/authorize", "/register", "/login"} {
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

func TestRevokedOAuthFamilyIsRefused(t *testing.T) {
	e := setupOAuth(t, nil)
	client := e.registerClient(t)
	access, refresh := e.grant(t, client)
	if code := post(t, e.url, "Bearer "+access); code == http.StatusUnauthorized {
		t.Fatal("fresh OAuth token refused")
	}
	resp, err := http.PostForm(e.url+"/revoke", url.Values{"token": {refresh}, "client_id": {client}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if code := post(t, e.url, "Bearer "+access); code != http.StatusUnauthorized {
		t.Fatalf("access token of a revoked family: %d, want 401", code)
	}
}

// Two registrations may share a display name (DCR takes client_name as
// given), so neither the rate limit nor the session cap may key on it.
func TestOAuthClientsWithTheSameNameHaveSeparateBudgets(t *testing.T) {
	e := setupOAuth(t, func(c *config.Config) { c.Limits.RequestsPerMinute = 6 }) // burst 1
	a, _ := e.grant(t, e.registerClient(t))
	b, _ := e.grant(t, e.registerClient(t))
	if code := post(t, e.url, "Bearer "+a); code == http.StatusTooManyRequests {
		t.Fatal("first request was rate limited")
	}
	if code := post(t, e.url, "Bearer "+a); code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d, want 429", code)
	}
	if code := post(t, e.url, "Bearer "+b); code == http.StatusTooManyRequests {
		t.Fatal("a different grant with the same client name shared the budget")
	}
}

func TestOAuthClientsWithTheSameNameHaveSeparateSessionCaps(t *testing.T) {
	e := setupOAuth(t, manySessions)
	a, _ := e.grant(t, e.registerClient(t))
	b, _ := e.grant(t, e.registerClient(t))
	raw := env{url: e.url}
	for i := 0; i < maxSessionsPerClient; i++ {
		if code, _, _, _ := rawInit(t, raw, a); code != http.StatusOK {
			t.Fatalf("session %d: %d", i, code)
		}
	}
	if code, _, _, _ := rawInit(t, raw, a); code != http.StatusTooManyRequests {
		t.Fatalf("session over the cap: %d, want 429", code)
	}
	if code, _, _, _ := rawInit(t, raw, b); code != http.StatusOK {
		t.Fatalf("other grant with the same client name: %d, want 200", code)
	}
}

// Sessions are bound to UserID, so a refresh must keep it: the grant family,
// not the access token.
func TestOAuthUserIDSurvivesRefresh(t *testing.T) {
	e := setupOAuth(t, nil)
	client := e.registerClient(t)
	access, refresh := e.grant(t, client)
	status, out := e.refresh(t, client, refresh)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d", status)
	}
	next, _ := out["access_token"].(string)
	before, err := e.svc.Verify(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	after, err := e.svc.Verify(t.Context(), next)
	if err != nil {
		t.Fatal(err)
	}
	if before.UserID != after.UserID {
		t.Fatal("UserID changed across a refresh")
	}
	if code := post(t, e.url, "Bearer "+next); code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("refreshed token: %d", code)
	}
}
