package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/server"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

// drainTimeout is how long shutdown waits for in-flight requests.
const drainTimeout = 10 * time.Second

// serve listens on cfg.Listen and runs until ctx is cancelled.
func serve(ctx context.Context, cfg config.Config, lg *slog.Logger) error {
	warnExposedListen(cfg, lg)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	return serveOn(ctx, cfg, ln, lg, drainTimeout)
}

// warnExposedListen warns when public_url is https (so TLS ends in a proxy)
// but the listener is not loopback-only: the plain-HTTP port is then
// reachable from the network, bypassing the proxy. It is a warning, not an
// error, because containers must bind ":8080" and rely on the runtime's
// port mapping instead.
func warnExposedListen(cfg config.Config, lg *slog.Logger) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Scheme != "https" {
		return
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || config.IsLoopbackHost(host) {
		return
	}
	lg.Warn("listen is not loopback while public_url is https: the plain HTTP port may be reachable without the TLS proxy; bind 127.0.0.1 unless a container runtime maps the port",
		"listen", cfg.Listen)
}

// vaultOptions maps the config onto the vault. The instructions file is
// read-only for tools: every assistant receives it, so one that could edit
// it could rewrite the rules for all of them.
func vaultOptions(cfg config.Config) vault.Options {
	o := vault.Options{Deny: cfg.Deny, MaxWriteBytes: cfg.Limits.MaxWriteBytes}
	if cfg.InstructionsFile != "" {
		o.ReadOnly = []string{cfg.InstructionsFile}
	}
	return o
}

// serveOn serves on ln until ctx is cancelled, then drains requests for up
// to drain. It owns ln and every resource it opens, and releases them in
// reverse order of acquisition.
func serveOn(ctx context.Context, cfg config.Config, ln net.Listener, lg *slog.Logger, drain time.Duration) error {
	defer func() { _ = ln.Close() }() // no-op after a clean Shutdown; covers early returns
	v, err := vault.New(cfg.Vault, vaultOptions(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	store, err := tokens.Open(filepath.Join(cfg.StateDir, "auth.db"))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	wl, err := logs.Open(cfg.StateDir, int64(cfg.Logs.MaxSizeMB)<<20, cfg.Logs.Keep)
	if err != nil {
		return err
	}
	defer func() { _ = wl.Close() }()

	// Every request context derives from base, which is cancelled when
	// Shutdown starts: Shutdown alone waits for active connections to go
	// idle, and an open SSE event stream never does, so without this every
	// shutdown with a connected client would hit the drain timeout.
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	// There is deliberately no WriteTimeout: it would cut off long-lived SSE
	// streams. ReadTimeout is safe because request bodies are capped (about
	// twice max_write_bytes, see server.New).
	srv := &http.Server{
		Handler:           server.New(server.Options{Config: cfg, Vault: v, Tokens: store, Log: wl, Logger: lg}),
		BaseContext:       func(net.Listener) context.Context { return base },
		ReadHeaderTimeout: 10 * time.Second, // slow-header (Slowloris) protection
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	srv.RegisterOnShutdown(cancelBase)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	lg.Info("cortex-mcp listening", "addr", ln.Addr().String(), "version", server.Version)
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		lg.Info("cortex-mcp shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), drain)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			// Force-close can leave handlers running against a closed vault;
			// that is safe because writes are atomic.
			_ = srv.Close()
			return fmt.Errorf("shutdown: drain timed out after %s: %w", drain, err)
		}
		return nil
	}
}
