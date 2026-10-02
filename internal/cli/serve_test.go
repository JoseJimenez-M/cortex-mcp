package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
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
