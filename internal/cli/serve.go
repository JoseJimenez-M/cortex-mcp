package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/server"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

// serve listens on cfg.Listen and runs until ctx is cancelled.
func serve(ctx context.Context, cfg config.Config, lg *slog.Logger) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	return serveOn(ctx, cfg, ln, lg)
}

// serveOn serves on ln until ctx is cancelled, then drains requests for up
// to 10s. It owns ln and every resource it opens, and releases them in
// reverse order of acquisition.
func serveOn(ctx context.Context, cfg config.Config, ln net.Listener, lg *slog.Logger) error {
	defer func() { _ = ln.Close() }() // no-op after a clean Shutdown; covers early returns
	v, err := vault.New(cfg.Vault, vault.Options{Deny: cfg.Deny, MaxWriteBytes: cfg.Limits.MaxWriteBytes})
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

	// There is deliberately no WriteTimeout: it would cut off long-lived SSE
	// streams. ReadTimeout is safe because request bodies are capped (~1 MiB).
	srv := &http.Server{
		Handler:           server.New(server.Options{Config: cfg, Vault: v, Tokens: store, Log: wl}),
		ReadHeaderTimeout: 10 * time.Second, // slow-header (Slowloris) protection
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
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
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close() // drain timed out: drop remaining connections
			return err
		}
		return nil
	}
}
