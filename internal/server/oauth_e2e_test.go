package server

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
)

// TestOAuthEndToEndWithTheSDKClient connects the go-sdk MCP client with its
// own OAuth handler: the server must satisfy a real MCP client's discovery,
// registration, PKCE, resource, and iss checks. The library logs through
// slog.Default, so that is captured and searched for secrets.
func TestOAuthEndToEndWithTheSDKClient(t *testing.T) {
	var logged syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	e := setupOAuthLogging(t, nil, &logged)
	var codes []string
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs:            []string{e2eRedirect},
			ClientName:              "e2e assistant",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}},
		RedirectURL:         e2eRedirect,
		RequestRefreshToken: true,
		AuthorizationCodeFetcher: func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			u, err := url.Parse(args.URL)
			if err != nil {
				return nil, err
			}
			if q := u.Query(); q.Get("resource") != e.url+"/mcp" || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), "vault") {
				t.Errorf("authorization URL %s", args.URL)
			}
			res, err := e.browserAuthorize(args.URL)
			if err != nil {
				return nil, err
			}
			codes = append(codes, res.Get("code"))
			return &auth.AuthorizationResult{Code: res.Get("code"), State: res.Get("state"), Iss: res.Get("iss")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "test"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.url + "/mcp", OAuthHandler: handler}, nil)
	if err != nil {
		t.Fatalf("connect with OAuth: %v", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "create_note", Arguments: map[string]any{"path": "e2e.md", "content": "# From OAuth\n"}})
	if err != nil || res.IsError {
		t.Fatalf("create_note over OAuth: %v %+v", err, res)
	}
	entries, err := logs.ReadSince(e.stateDir, time.Time{})
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Client != "e2e assistant" || entries[len(entries)-1].Tool != "create_note" {
		t.Fatalf("write log attribution: %+v, %v", entries, err)
	}

	ts, err := handler.TokenSource(ctx)
	if err != nil || ts == nil {
		t.Fatalf("token source: %v", err)
	}
	tok, err := ts.Token()
	if err != nil || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("token: %+v, %v", tok, err)
	}
	if len(codes) != 1 {
		t.Fatalf("%d authorizations, want 1", len(codes))
	}
	// The log is not printed on failure: it would put the secret in the
	// test output.
	for i, secret := range []string{tok.AccessToken, tok.RefreshToken, codes[0]} {
		if strings.Contains(logged.String(), secret) {
			t.Fatalf("secret %d (access, refresh, code) reached a log", i)
		}
	}
}

func TestRefreshRotationKeepsTheMCPSession(t *testing.T) {
	e := setupOAuth(t, nil)
	clientID := e.registerClient(t)
	access, refresh := e.grant(t, clientID)
	sid := connect(t, env{url: e.url}, access).ID()
	status, tok := e.refresh(t, clientID, refresh)
	if status != http.StatusOK || tok["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, tok)
	}
	if code := postWithSession(t, env{url: e.url}, tok["access_token"].(string), sid); code != http.StatusOK {
		t.Fatalf("refreshed token on the same session: %d, want 200", code)
	}
	// Another grant (even of the same client) cannot use this session.
	other, _ := e.grant(t, clientID)
	if code := postWithSession(t, env{url: e.url}, other, sid); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatalf("another grant on the session: %d, want 403 or 404", code)
	}
}

func TestRefreshReuseRevokesTheConnection(t *testing.T) {
	e := setupOAuth(t, nil)
	clientID := e.registerClient(t)
	_, r1 := e.grant(t, clientID)
	_, tok := e.refresh(t, clientID, r1)
	if status, out := e.refresh(t, clientID, r1); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("reused refresh token: %d %v", status, out)
	}
	if code := post(t, e.url, "Bearer "+tok["access_token"].(string)); code != http.StatusUnauthorized {
		t.Fatalf("access token after reuse: %d, want 401", code)
	}
	if status, _ := e.refresh(t, clientID, tok["refresh_token"].(string)); status != http.StatusBadRequest {
		t.Fatalf("newest refresh token after reuse: %d", status)
	}
}

func TestRevocationEndsAccess(t *testing.T) {
	e := setupOAuth(t, nil)
	clientID := e.registerClient(t)
	access, refresh := e.grant(t, clientID)
	resp, err := http.PostForm(e.url+"/revoke", url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}, "client_id": {clientID}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if code := post(t, e.url, "Bearer "+access); code != http.StatusUnauthorized {
		t.Fatalf("access token after revoking its refresh token: %d", code)
	}
	if code := post(t, e.url, "Bearer "+e.bearer); code == http.StatusUnauthorized {
		t.Fatal("revoking an OAuth grant affected a Bearer token")
	}
}

func TestAccessTokensExpireAfterAnHour(t *testing.T) {
	e := setupOAuth(t, nil)
	access, _ := e.grant(t, e.registerClient(t))
	e.clock.Advance(59 * time.Minute)
	if code := post(t, e.url, "Bearer "+access); code == http.StatusUnauthorized {
		t.Fatal("token refused before expiry")
	}
	e.clock.Advance(time.Minute)
	if code := post(t, e.url, "Bearer "+access); code != http.StatusUnauthorized {
		t.Fatalf("token after an hour: %d", code)
	}
}

func TestClientsRevokeCutsOneClientOnly(t *testing.T) {
	e := setupOAuth(t, nil)
	a, b := e.registerClient(t), e.registerClient(t)
	accessA, refreshA := e.grant(t, a)
	accessB, _ := e.grant(t, b)
	if err := e.svc.Store().RevokeClient(a); err != nil {
		t.Fatal(err)
	}
	if code := post(t, e.url, "Bearer "+accessA); code != http.StatusUnauthorized {
		t.Fatalf("revoked client's token: %d", code)
	}
	if status, _ := e.refresh(t, a, refreshA); status == http.StatusOK {
		t.Fatal("revoked client refreshed")
	}
	for name, tok := range map[string]string{"other client": accessB, "bearer": e.bearer} {
		if code := post(t, e.url, "Bearer "+tok); code == http.StatusUnauthorized {
			t.Errorf("%s refused after revoking another client", name)
		}
	}
}

// A store failure is the server's problem, not the client's: 500 without a
// WWW-Authenticate challenge (a challenge would send the client into a new
// authorization), and the operator log says why without the token.
func TestOAuthStoreFailureIs500WithoutChallenge(t *testing.T) {
	var logged syncBuffer
	e := setupOAuthLogging(t, nil, &logged)
	access, _ := e.grant(t, e.registerClient(t))
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	status, h := challengeOf(t, e.url, "Bearer "+access)
	if status != http.StatusInternalServerError || h != "" {
		t.Fatalf("store failure: %d %q, want 500 without a challenge", status, h)
	}
	if out := logged.String(); !strings.Contains(out, "oauth token store failure") || strings.Contains(out, access) {
		t.Fatalf("operator log:\n%s", out)
	}
}

// A token issued for another resource is not a token for this one, even
// though this server signed it (RFC 8707, spec 6).
func TestTokenForAnotherAudienceIsRefused(t *testing.T) {
	e := setupOAuth(t, nil)
	access, _ := e.grant(t, e.registerClient(t))
	if _, err := e.db.Exec(`UPDATE grants SET audience = 'https://other.example/mcp'`); err != nil {
		t.Fatal(err)
	}
	want := `Bearer resource_metadata="` + e.url + `/.well-known/oauth-protected-resource/mcp", scope="vault"`
	if status, h := challengeOf(t, e.url, "Bearer "+access); status != http.StatusUnauthorized || h != want {
		t.Fatalf("token for another audience: %d %q", status, h)
	}
}

// TestNoSecretReachesAnyLog runs every flow (TOTP and recovery code logins,
// a failed login, code exchange, MCP use, refresh, reuse detection,
// revocation, expiry, a store failure) with every log captured: the
// library's default logger, the server's and the OAuth service's operator
// logs, and the files in the state directory. None may contain a secret.
func TestNoSecretReachesAnyLog(t *testing.T) {
	var logged syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	e := setupOAuthLogging(t, nil, &logged)
	e.seen = &secretSet{}
	e.seen.add(e.bearer)
	e.seen.add(e.recovery...)
	clientID := e.registerClient(t)

	// A failed login: a wrong TOTP code.
	wrong := totpCode(e.totp, e.clock.Now().Add(time.Hour))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {e2eRedirect}, "state": {"s"}, "scope": {"vault"},
		"code_challenge": {s256(rand.Text())}, "code_challenge_method": {"S256"}, "resource": {e.url + "/mcp"}}
	if _, err := e.browserAuthorizeWith(e.url+"/authorize?"+q.Encode(), func() string { return wrong }); err == nil {
		t.Fatal("login with a wrong code succeeded")
	}
	e.seen.add(wrong)

	// A recovery code login, then its code exchange.
	verifier := rand.Text() + rand.Text()
	e.seen.add(verifier)
	q.Set("code_challenge", s256(verifier))
	res, err := e.browserAuthorizeWith(e.url+"/authorize?"+q.Encode(), func() string { return e.recovery[0] })
	if err != nil {
		t.Fatalf("recovery code login: %v", err)
	}
	status, tok := e.tokenRequest(t, url.Values{"grant_type": {"authorization_code"}, "code": {res.Get("code")}, "redirect_uri": {e2eRedirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {e.url + "/mcp"}})
	if status != http.StatusOK {
		t.Fatalf("token after recovery login: %d %v", status, tok)
	}
	e.seen.add(tok["access_token"].(string), tok["refresh_token"].(string))

	// A TOTP login, MCP use, a refresh, reuse of the old refresh token.
	access, r1 := e.grant(t, clientID)
	cs := connect(t, env{url: e.url}, access)
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "create_note", Arguments: map[string]any{"path": "s.md", "content": "x"}}); err != nil || res.IsError {
		t.Fatalf("create_note: %v %+v", err, res)
	}
	if status, _ := e.refresh(t, clientID, r1); status != http.StatusOK {
		t.Fatalf("refresh: %d", status)
	}
	if status, _ := e.refresh(t, clientID, r1); status != http.StatusBadRequest {
		t.Fatalf("refresh reuse: %d", status)
	}
	if code := post(t, e.url, "Bearer "+access); code != http.StatusUnauthorized {
		t.Fatalf("access token after reuse: %d", code)
	}

	// Revocation, and a token used after it expired.
	access2, r2 := e.grant(t, clientID)
	resp, err := http.PostForm(e.url+"/revoke", url.Values{"token": {r2}, "client_id": {clientID}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	access3, _ := e.grant(t, clientID)
	e.clock.Advance(time.Hour)
	for _, a := range []string{access2, access3} {
		if code := post(t, e.url, "Bearer "+a); code != http.StatusUnauthorized {
			t.Fatalf("revoked or expired token: %d", code)
		}
	}

	// A store failure logs an error that must not carry the token either.
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	if code := post(t, e.url, "Bearer "+access3); code != http.StatusInternalServerError {
		t.Fatalf("store failure: %d", code)
	}

	var files strings.Builder
	err = filepath.WalkDir(e.stateDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), "auth.db") {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- a file in the test's own temp dir
		files.Write(b)
		return err
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if logged.String() == "" || files.Len() == 0 {
		t.Fatal("nothing was logged: the check below would be vacuous")
	}
	secrets := e.seen.list()
	if len(secrets) < 20 {
		t.Fatalf("only %d secrets recorded", len(secrets))
	}
	for i, secret := range secrets {
		if strings.Contains(logged.String(), secret) || strings.Contains(files.String(), secret) {
			t.Fatalf("secret %d (of %d recorded) reached a log", i, len(secrets))
		}
	}
}
