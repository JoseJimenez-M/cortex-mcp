package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

// clock is a settable time source safe for the server's goroutines.
type clock struct{ ns atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *clock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

type env struct {
	url, secret, stateDir, vaultDir string
	store                           *tokens.Store
	clock                           *clock
}

func setup(t *testing.T, mutate func(*config.Config)) env {
	t.Helper()
	vaultDir, stateDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(vaultDir, "AGENTS.md"), []byte("Write in English."), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Vault, cfg.StateDir, cfg.PublicURL, cfg.InstructionsFile = vaultDir, stateDir, "http://localhost", "AGENTS.md"
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := vault.New(vaultDir, vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := tokens.Open(filepath.Join(stateDir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := logs.Open(stateDir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.Create("test-client")
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{}
	clk.ns.Store(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).UnixNano())
	ts := httptest.NewServer(New(Options{Config: cfg, Vault: v, Tokens: store, Log: lg, Now: clk.Now}))
	t.Cleanup(func() {
		ts.Close()
		_ = lg.Close()
		_ = store.Close()
		_ = v.Close()
	})
	return env{url: ts.URL, secret: secret, stateDir: stateDir, vaultDir: vaultDir, store: store, clock: clk}
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func connect(t *testing.T, e env, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "it", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.url + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func doPost(t *testing.T, url, auth, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

const pingBody = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

func post(t *testing.T, url, auth string) int {
	t.Helper()
	resp := doPost(t, url, auth, pingBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestMCPOverHTTPWithBearer(t *testing.T) {
	e := setup(t, nil)
	cs := connect(t, e, e.secret)
	instr := cs.InitializeResult().Instructions
	if !strings.HasPrefix(instr, DefaultInstructions) || !strings.Contains(instr, "Write in English.") {
		t.Fatalf("instructions = %q", instr)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "create_note", Arguments: map[string]any{"path": "a.md", "content": "hi"}})
	if err != nil || res.IsError {
		t.Fatalf("create_note: %v %+v", err, res)
	}
	got, _ := logs.ReadSince(e.stateDir, time.Time{})
	if len(got) != 1 || got[0].Client != "test-client" {
		t.Fatalf("log = %+v", got)
	}
}

func TestMCPRequiresAValidToken(t *testing.T) {
	e := setup(t, nil)
	for _, h := range []string{"", "Bearer nope", "Bearer cmcp_wrong", "Basic abc", "Bearer", "Bearer a b"} {
		if code := post(t, e.url, h); code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status %d, want 401", h, code)
		}
	}
}

func TestMCPRejectsEveryMethodWithoutAuth(t *testing.T) {
	e := setup(t, nil)
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodOptions, http.MethodPost} {
		req, _ := http.NewRequest(m, e.url+"/mcp", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without auth: status %d, want 401", m, resp.StatusCode)
		}
	}
}

func TestRevokedTokenStopsWorking(t *testing.T) {
	e := setup(t, nil)
	if code := post(t, e.url, "Bearer "+e.secret); code == http.StatusUnauthorized {
		t.Fatal("valid token rejected")
	}
	if err := e.store.Revoke("test-client"); err != nil {
		t.Fatal(err)
	}
	if code := post(t, e.url, "Bearer "+e.secret); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d, want 401", code)
	}
}

func TestRateLimitPerClient(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Limits.RequestsPerMinute = 6 }) // burst 1
	other, err := e.store.Create("other-client")
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, e.url, "Bearer "+e.secret); code == http.StatusTooManyRequests {
		t.Fatal("first request was rate limited")
	}
	resp := doPost(t, e.url, "Bearer "+e.secret, pingBody)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request: status %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" || strings.Contains(string(body), "test-client") || strings.Contains(string(body), e.secret) {
		t.Fatalf("429 must carry Retry-After and leak nothing: %v %q", resp.Header, body)
	}
	if code := post(t, e.url, "Bearer "+other); code == http.StatusTooManyRequests {
		t.Fatal("another client was limited by the first one's traffic")
	}
}

func TestUnauthenticatedRequestsDoNotConsumeClientBudget(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Limits.RequestsPerMinute = 6 })
	for range 5 {
		post(t, e.url, "Bearer cmcp_wrong")
	}
	if code := post(t, e.url, "Bearer "+e.secret); code == http.StatusTooManyRequests {
		t.Fatal("failed auth attempts drained a client's budget")
	}
}

func TestHealthz(t *testing.T) {
	e := setup(t, nil)
	resp, err := http.Get(e.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok\n" {
		t.Fatalf("healthz = %d %q", resp.StatusCode, b)
	}
	if resp.Header.Get("Server") != "" || strings.Contains(strings.ToLower(resp.Header.Get("X-Version")), "dev") {
		t.Fatalf("healthz leaks version info: %v", resp.Header)
	}
	post, err := http.Post(e.url+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", post.StatusCode)
	}
}

func TestUnknownPathIs404WithoutDetails(t *testing.T) {
	e := setup(t, nil)
	for _, p := range []string{"/", "/admin", "/mcp/", "/.well-known/oauth-protected-resource"} {
		resp, err := http.Get(e.url + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || strings.TrimSpace(string(b)) != "404 page not found" {
			t.Errorf("%s = %d %q", p, resp.StatusCode, b)
		}
	}
}

func TestDefenceHeaders(t *testing.T) {
	e := setup(t, nil)
	for _, c := range []struct {
		name, method, path, auth string
		noStore                  bool
	}{
		{"mcp 401", http.MethodPost, "/mcp", "", true},
		{"mcp 200", http.MethodPost, "/mcp", "Bearer " + e.secret, true},
		{"healthz", http.MethodGet, "/healthz", "", false},
		{"404", http.MethodGet, "/nope", "", false},
	} {
		req, _ := http.NewRequest(c.method, e.url+c.path, strings.NewReader(pingBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Origin", "https://evil.example")
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", c.name)
		}
		if c.noStore && resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", c.name, resp.Header.Get("Cache-Control"))
		}
		for h := range resp.Header {
			if strings.HasPrefix(strings.ToLower(h), "access-control-") {
				t.Errorf("%s: unexpected CORS header %s", c.name, h)
			}
		}
	}
}

func TestOversizedBodyRejectedBeforeTools(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Limits.MaxWriteBytes = 1024 })
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_note","arguments":{"path":"big.md","content":"` +
		strings.Repeat("a", 200<<10) + `"}}}`
	resp := doPost(t, e.url, "Bearer "+e.secret, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(e.vaultDir, "big.md")); err == nil {
		t.Fatal("oversized write reached the vault")
	}
	if got, _ := logs.ReadSince(e.stateDir, time.Time{}); len(got) != 0 {
		t.Fatalf("tool ran: %+v", got)
	}
}

func TestSecretNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	e := setup(t, nil)
	bad := "cmcp_" + strings.Repeat("A", 43)
	post(t, e.url, "Bearer "+bad)
	post(t, e.url, "Bearer "+e.secret)
	connect(t, e, e.secret)
	for _, s := range []string{bad, e.secret, "Bearer"} {
		if strings.Contains(buf.String(), s) {
			t.Fatalf("log output contains %q:\n%s", s, buf.String())
		}
	}
}

func TestInstructionsEditsApplyToNewSessions(t *testing.T) {
	e := setup(t, nil)
	if !strings.Contains(connect(t, e, e.secret).InitializeResult().Instructions, "Write in English.") {
		t.Fatal("initial instructions missing")
	}
	if err := os.WriteFile(filepath.Join(e.vaultDir, "AGENTS.md"), []byte("Write in Spanish."), 0o644); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(instructionsTTL + time.Second)
	got := connect(t, e, e.secret).InitializeResult().Instructions
	if !strings.Contains(got, "Write in Spanish.") || !strings.HasPrefix(got, DefaultInstructions) {
		t.Fatalf("instructions = %q", got)
	}
}

func TestInstructionsFallbackAndTruncation(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.InstructionsFile = "missing.md" })
	if got := connect(t, e, e.secret).InitializeResult().Instructions; got != DefaultInstructions {
		t.Fatalf("missing file: instructions = %q", got)
	}

	e = setup(t, func(c *config.Config) { c.InstructionsFile = "" })
	if got := connect(t, e, e.secret).InitializeResult().Instructions; got != DefaultInstructions {
		t.Fatalf("no file configured: instructions = %q", got)
	}

	vaultDir := t.TempDir()
	huge := strings.Repeat("é", maxInstructionsBytes) // 2 bytes per rune
	if err := os.WriteFile(filepath.Join(vaultDir, "AGENTS.md"), []byte(huge), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(vaultDir, vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	cfg := config.Default()
	cfg.InstructionsFile = "AGENTS.md"
	got := Options{Config: cfg, Vault: v}.instructions()
	if len(got) > len(DefaultInstructions)+maxInstructionsBytes+200 || !strings.HasSuffix(got, truncationNote) {
		t.Fatalf("not truncated: len %d", len(got))
	}
	if !strings.HasPrefix(got, DefaultInstructions) {
		t.Fatal("defaults must come first")
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Fatal("truncation split a rune")
	}
}

func TestSessionBoundToToken(t *testing.T) {
	e := setup(t, nil)
	other, err := e.store.Create("other-client")
	if err != nil {
		t.Fatal(err)
	}
	cs := connect(t, e, e.secret)
	sid := cs.ID()
	req, _ := http.NewRequest(http.MethodPost, e.url+"/mcp", strings.NewReader(pingBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+other)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("hijack attempt: status %d, want 403", resp.StatusCode)
	}
}
