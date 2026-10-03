package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
)

func TestServeOnShutsDownCleanly(t *testing.T) {
	cfg, err := config.Load(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveOn(ctx, cfg, ln, slog.New(slog.NewJSONHandler(io.Discard, nil)), 5*time.Second) }()

	url := "http://" + ln.Addr().String() + "/healthz"
	var resp *http.Response
	for i := 0; i < 100; i++ {
		if resp, err = http.Get(url); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}

	// Unauthenticated MCP requests must be refused (invariant 7).
	r2, err := http.Post("http://"+ln.Addr().String()+"/mcp", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp: %d", r2.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveOn did not return after cancel")
	}
}

func TestServeReportsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path := writeConfig(t)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = ln.Addr().String()
	var errb bytes.Buffer
	err = serve(context.Background(), cfg, slog.New(slog.NewJSONHandler(&errb, nil)))
	if err == nil {
		t.Fatal("want listen error")
	}
}

func TestServeOnDrainTimeout(t *testing.T) {
	cfg, err := config.Load(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveOn(ctx, cfg, ln, slog.New(slog.NewJSONHandler(io.Discard, nil)), 100*time.Millisecond)
	}()
	// A half-sent request keeps its connection active, so the drain stalls.
	var conn net.Conn
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("tcp", ln.Addr().String()); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "shutdown: drain timed out after 100ms") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveOn did not return")
	}
}

func TestVaultOptionsProtectInstructionsFile(t *testing.T) {
	cfg := config.Default()
	cfg.Deny = []string{"Private"}
	cfg.Limits.MaxWriteBytes = 4096
	o := vaultOptions(cfg)
	if len(o.ReadOnly) != 0 || !slices.Equal(o.Deny, cfg.Deny) || o.MaxWriteBytes != 4096 {
		t.Fatalf("no instructions file: %+v", o)
	}
	cfg.InstructionsFile = "AGENTS.md"
	if o := vaultOptions(cfg); !slices.Equal(o.ReadOnly, []string{"AGENTS.md"}) {
		t.Fatalf("ReadOnly = %v, want the instructions file", o.ReadOnly)
	}
}

// syncBuffer is a bytes.Buffer safe for the server's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestServeOnEndsOpenStreamsOnShutdown(t *testing.T) {
	cfg, err := config.Load(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.InstructionsFile = "missing.md" // makes the server log on the injected logger
	store, err := tokens.Open(filepath.Join(cfg.StateDir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.Create("it")
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var logBuf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveOn(ctx, cfg, ln, slog.New(slog.NewJSONHandler(&logBuf, nil)), drainTimeout) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "it", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   "http://" + ln.Addr().String() + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{secret}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if _, err := cs.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the client open its event stream

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveOn: %v", err)
		}
		if d := time.Since(start); d > drainTimeout/4 {
			t.Fatalf("shutdown took %s with a stream open", d)
		}
	case <-time.After(drainTimeout + 5*time.Second):
		t.Fatal("serveOn did not return")
	}
	if !strings.Contains(logBuf.String(), "instructions file unreadable") {
		t.Fatalf("server did not log on the serve logger:\n%s", logBuf.String())
	}
}

func TestWarnExposedListen(t *testing.T) {
	cases := []struct {
		url, listen string
		warn        bool
	}{
		{"https://mcp.example.com", ":8080", true},
		{"https://mcp.example.com", "0.0.0.0:8080", true},
		{"https://mcp.example.com", "[::]:8080", true},
		{"https://mcp.example.com", "192.168.1.5:8080", true},
		{"https://mcp.example.com", "127.0.0.1:8080", false},
		{"https://mcp.example.com", "localhost:8080", false},
		{"https://mcp.example.com", "[::1]:8080", false},
		{"http://localhost:8080", ":8080", false},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		cfg := config.Default()
		cfg.PublicURL, cfg.Listen = c.url, c.listen
		warnExposedListen(cfg, slog.New(slog.NewJSONHandler(&buf, nil)))
		got := strings.Contains(buf.String(), `"level":"WARN"`)
		if got != c.warn {
			t.Errorf("public_url %s listen %s: warned=%v, want %v (%s)", c.url, c.listen, got, c.warn, buf.String())
		}
	}
}

// startServe runs serveOn on a free port and returns its base URL and a stop
// function that waits for a clean shutdown.
func startServe(t *testing.T, cfgPath string) (string, func()) {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveOn(ctx, cfg, ln, slog.New(slog.NewJSONHandler(io.Discard, nil)), 5*time.Second) }()
	base := "http://" + ln.Addr().String()
	for i := 0; i < 100; i++ {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return base, func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serveOn: %v", err)
		}
	}
}

func TestServeMountsOAuth(t *testing.T) {
	base, stop := startServe(t, writeConfig(t))
	defer stop()
	resp, err := http.Get(base + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AS metadata: %d", resp.StatusCode)
	}
	r2, err := http.Post(base+"/mcp", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized || !strings.Contains(r2.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("/mcp: %d %q", r2.StatusCode, r2.Header.Get("WWW-Authenticate"))
	}
}

func TestServeWithOAuthDisabled(t *testing.T) {
	base, stop := startServe(t, writeConfigExtra(t, "oauth:\n  enabled: false\n"))
	defer stop()
	resp, err := http.Get(base + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AS metadata with OAuth off: %d", resp.StatusCode)
	}
}

func TestServeRefusesBearerOffBeforeSetup(t *testing.T) {
	cfg, err := config.Load(writeConfigExtra(t, "bearer_tokens: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The timeout only bounds a regression (serveOn starting and serving);
	// the refusal itself returns at once.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = serveOn(ctx, cfg, ln, slog.New(slog.NewJSONHandler(io.Discard, nil)), time.Second)
	if err == nil || !strings.Contains(err.Error(), "cortex-mcp setup") {
		t.Fatalf("serveOn = %v", err)
	}
}

// TestAuthCommandsWhileServing is the production flow: the CLI runs inside
// the container (docker compose exec) against the auth.db that serve holds
// open, and serve sees the result without a restart.
func TestAuthCommandsWhileServing(t *testing.T) {
	cfg := writeConfig(t)
	base, stop := startServe(t, cfg)
	defer stop()
	code, out, errOut := run("setup", "-config", cfg)
	if code != 0 || !strings.Contains(out, "http://localhost:8080/enroll#") {
		t.Fatalf("setup while serving: %d %q", code, errOut)
	}
	link := out[strings.Index(out, "/enroll#")+len("/enroll#"):]
	link = strings.TrimSpace(link[:strings.Index(link, "\n")+1])
	// The running server accepts the enrollment link the CLI just wrote:
	// a bad code is refused as a bad code (401), not as an invalid link (400).
	resp, err := http.Post(base+"/enroll/begin", "application/json",
		strings.NewReader(`{"token":"`+link+`","code":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enroll/begin with a fresh link and a wrong code: %d", resp.StatusCode)
	}
	for _, args := range [][]string{
		{"setup", "-config", cfg, "-passkey"},
		{"unlock-totp", "-config", cfg},
		{"clients", "list", "-config", cfg},
		{"setup", "-config", cfg, "-force"},
		{"reset-auth", "-config", cfg, "-yes"},
	} {
		if code, _, errOut := run(args...); code != 0 {
			t.Fatalf("%v while serving: %d %q", args, code, errOut)
		}
	}
}

func TestWarnSharedRateLimits(t *testing.T) {
	cases := []struct {
		url     string
		proxies []string
		oauth   bool
		warn    bool
	}{
		{"https://mcp.example.com", nil, true, true},
		{"https://mcp.example.com", []string{"172.18.0.0/16"}, true, false},
		{"https://mcp.example.com", nil, false, false},
		{"http://localhost:8080", nil, true, false},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		cfg := config.Default()
		cfg.PublicURL, cfg.TrustedProxies, cfg.OAuth.Enabled = c.url, c.proxies, c.oauth
		warnSharedRateLimits(cfg, slog.New(slog.NewJSONHandler(&buf, nil)))
		got := strings.Contains(buf.String(), `"level":"WARN"`) && strings.Contains(buf.String(), "trusted_proxies")
		if got != c.warn {
			t.Errorf("%+v: warned=%v (%s)", c, got, buf.String())
		}
	}
}
