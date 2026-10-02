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
