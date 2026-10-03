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
	"strconv"
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
  cortex-mcp setup [-config path] [-passkey | -force]
  cortex-mcp unlock-totp [-config path]
  cortex-mcp reset-auth [-config path] [-yes]
  cortex-mcp clients list [-config path]
  cortex-mcp clients revoke [-config path] ID
  cortex-mcp token create [-config path] NAME
  cortex-mcp token list [-config path]
  cortex-mcp token revoke [-config path] NAME
  cortex-mcp version

setup creates the owner's login factors and prints them once. -passkey only
issues another passkey enrollment link. -force replaces every factor: the
current passkeys, authenticator entry and recovery codes stop working.
unlock-totp clears the lock after too many wrong authenticator codes.
reset-auth deletes the owner's factors and every OAuth client and grant,
keeping Bearer tokens; it asks you to type "reset" unless -yes is given.
clients revoke takes an id from clients list, or a name that matches one
credential only.

Flags go before NAME and ID. The config path defaults to $CORTEX_MCP_CONFIG,
then /etc/cortex-mcp/config.yaml.
`

// Run executes one command and returns the exit code: 0 ok, 1 failure, 2 usage.
// stdin is read only by reset-auth, for its typed confirmation.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
		// The OAuth library logs protocol errors through slog.Default; send
		// them to the same JSON stream. Our storage never puts a secret in
		// an error it hands to the library (internal/oauth/AGENTS.md).
		slog.SetDefault(lg)
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
	case "setup":
		var passkeyOnly, force bool
		p := parse("setup", args[1:], 0, stdout, stderr, func(fs *flag.FlagSet) {
			// Each flag refuses the other while parsing, so the conflict is
			// a usage error (exit 2) before the config is even read.
			fs.BoolFunc("passkey", "only issue a new passkey enrollment link", exclusiveBool(&passkeyOnly, &force))
			fs.BoolFunc("force", "replace the owner's factors; the current ones stop working", exclusiveBool(&force, &passkeyOnly))
		})
		if p.done {
			return p.code
		}
		return setup(p.cfg, passkeyOnly, force, stdout, stderr)
	case "unlock-totp":
		p := parse("unlock-totp", args[1:], 0, stdout, stderr)
		if p.done {
			return p.code
		}
		return unlockTOTP(p.cfg, stdout, stderr)
	case "reset-auth":
		var yes bool
		p := parse("reset-auth", args[1:], 0, stdout, stderr, func(fs *flag.FlagSet) {
			fs.BoolVar(&yes, "yes", false, "confirm without the typed prompt")
		})
		if p.done {
			return p.code
		}
		return resetAuth(p.cfg, yes, stdin, stdout, stderr)
	case "clients":
		if len(args) < 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return clients(args[1], args[2:], stdout, stderr)
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

// exclusiveBool sets *dst from a boolean flag value and fails when *other
// is already set, for two flags that cannot be combined.
func exclusiveBool(dst, other *bool) func(string) error {
	return func(v string) error {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		if b && *other {
			return errors.New("-passkey and -force cannot be combined")
		}
		*dst = b
		return nil
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

// parse reads -config, any flags that extra registers, and exactly nargs
// positional arguments, then loads the config.
func parse(name string, args []string, nargs int, stdout, stderr io.Writer, extra ...func(*flag.FlagSet)) parsed {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", defaultConfigPath(), "path to the config file")
	for _, f := range extra {
		f(fs)
	}
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
			fmt.Fprintf(stdout, "%s\tcreated %s\tlast used %s\n", r.Name, r.Created.Format(time.RFC3339), lastUsed(r.LastUsed))
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
