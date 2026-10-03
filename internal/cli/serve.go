package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/oauth"
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

// oauthService builds the authorization server when oauth.enabled is true
// (nil otherwise), and refuses bearer_tokens: false until the owner exists:
// config validation cannot see the database, and without an owner no
// client could authenticate at all.
func oauthService(cfg config.Config, db *sql.DB, lg *slog.Logger) (*oauth.Service, error) {
	owner, err := oauth.NewStore(db, nil).OwnerExists()
	if err != nil {
		return nil, err
	}
	if !cfg.BearerTokens && !owner {
		return nil, errors.New("bearer_tokens is false but OAuth is not set up: run cortex-mcp setup first, or set bearer_tokens: true")
	}
	if !cfg.OAuth.Enabled {
		return nil, nil
	}
	if !owner {
		lg.Warn("OAuth is enabled but not set up: assistants cannot log in until you run cortex-mcp setup")
	}
	warnSharedRateLimits(cfg, lg)
	return oauth.New(oauth.Options{
		DB: db, PublicURL: cfg.PublicURL, RedirectAllowlist: cfg.OAuth.RedirectAllowlist,
		TrustedProxies: cfg.TrustedProxies, Logger: lg,
	})
}

// warnSharedRateLimits warns when public_url is https (so a proxy sits in
// front) and trusted_proxies is empty: every request then comes from the
// proxy's address, and the per-source limits on login and client
// registration collapse into one bucket that one attacker can exhaust for
// everyone, the owner included. It is a warning because that is safe, only
// coarse, and a direct https listener (no proxy) is not wrong.
func warnSharedRateLimits(cfg config.Config, lg *slog.Logger) {
	if !cfg.OAuth.Enabled || len(cfg.TrustedProxies) > 0 {
		return
	}
	if u, err := url.Parse(cfg.PublicURL); err != nil || u.Scheme != "https" {
		return
	}
	lg.Warn("public_url is https but trusted_proxies is empty: behind a reverse proxy every client shares one rate-limit bucket for login and registration; set trusted_proxies to the proxy's network")
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
	// One connection to auth.db for both token kinds (authdb.Open).
	db, err := authdb.Open(filepath.Join(cfg.StateDir, "auth.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	store := tokens.New(db)
	svc, err := oauthService(cfg, db, lg)
	if err != nil {
		return err
	}
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
		Handler:           server.New(server.Options{Config: cfg, Vault: v, Tokens: store, OAuth: svc, Log: wl, Logger: lg}),
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
