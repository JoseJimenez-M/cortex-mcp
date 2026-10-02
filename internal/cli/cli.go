// Package cli implements the cortex-mcp command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/server"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
)

const usage = `cortex-mcp: an MCP server for a Markdown vault

Usage:
  cortex-mcp serve [-config path]
  cortex-mcp token create [-config path] NAME
  cortex-mcp token list [-config path]
  cortex-mcp token revoke [-config path] NAME
  cortex-mcp version

Flags go before NAME. The config path defaults to $CORTEX_MCP_CONFIG, then
/etc/cortex-mcp/config.yaml.
`

// Run executes one command and returns the exit code: 0 ok, 1 failure, 2 usage.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		fmt.Fprintln(stdout, "cortex-mcp", server.Version)
		return 0
	case "serve":
		p := parse("serve", args[1:], 0, stdout, stderr)
		if p.done {
			return p.code
		}
		// Server logs are machine-read, so they are JSON on stderr.
		lg := slog.New(slog.NewJSONHandler(stderr, nil))
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			// Restore default signal handling after the first signal so a
			// second SIGINT/SIGTERM kills the process at once instead of
			// waiting for a stuck drain.
			<-ctx.Done()
			stop()
		}()
		if err := serve(ctx, p.cfg, lg); err != nil {
			fmt.Fprintln(stderr, "serve:", err)
			return 1
		}
		return 0
	case "token":
		if len(args) < 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return token(args[1], args[2:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func defaultConfigPath() string {
	if p := os.Getenv("CORTEX_MCP_CONFIG"); p != "" {
		return p
	}
	return "/etc/cortex-mcp/config.yaml"
}

// parsed is the outcome of parse. When done is set the command is already
// finished (help shown, usage error, or config failure) with exit code code.
type parsed struct {
	cfg  config.Config
	rest []string
	code int
	done bool
}

// parse reads -config and exactly nargs positional arguments, then loads
// the config.
func parse(name string, args []string, nargs int, stdout, stderr io.Writer) parsed {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", defaultConfigPath(), "path to the config file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return parsed{done: true}
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usage)
		return parsed{code: 2, done: true}
	}
	if fs.NArg() != nargs {
		// Go's flag package stops at the first positional argument, so a
		// flag placed after NAME arrives here as an extra argument.
		for _, a := range fs.Args() {
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "%s: unexpected %q: flags must come before NAME\n", name, a)
				return parsed{code: 2, done: true}
			}
		}
		fmt.Fprintf(stderr, "%s: expected %d argument(s), got %d\n", name, nargs, fs.NArg())
		fmt.Fprint(stderr, usage)
		return parsed{code: 2, done: true}
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return parsed{code: 1, done: true}
	}
	return parsed{cfg: cfg, rest: fs.Args()}
}

func token(sub string, args []string, stdout, stderr io.Writer) int {
	nargs, ok := map[string]int{"create": 1, "list": 0, "revoke": 1}[sub]
	if !ok {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p := parse("token "+sub, args, nargs, stdout, stderr)
	if p.done {
		return p.code
	}
	store, err := tokens.Open(filepath.Join(p.cfg.StateDir, "auth.db"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = store.Close() }()
	switch sub {
	case "create":
		secret, err := store.Create(p.rest[0])
		if err != nil {
			fmt.Fprintln(stderr, "token create:", err)
			return 1
		}
		fmt.Fprintln(stdout, secret)
		fmt.Fprintln(stderr, "Store this token now: it is shown only once and kept only as a hash.")
	case "list":
		recs, err := store.List()
		if err != nil {
			fmt.Fprintln(stderr, "token list:", err)
			return 1
		}
		for _, r := range recs {
			last := "never"
			if !r.LastUsed.IsZero() {
				last = r.LastUsed.Format(time.RFC3339)
			}
			fmt.Fprintf(stdout, "%s\tcreated %s\tlast used %s\n", r.Name, r.Created.Format(time.RFC3339), last)
		}
	case "revoke":
		if err := store.Revoke(p.rest[0]); err != nil {
			fmt.Fprintln(stderr, "token revoke:", err)
			return 1
		}
		fmt.Fprintln(stdout, "revoked", p.rest[0])
	}
	return 0
}
