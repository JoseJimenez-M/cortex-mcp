package cli

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/oauth"
	"github.com/JoseJimenez-M/cortex-mcp/internal/tokens"
)

// resetConfirmation is what reset-auth wants typed when -yes is absent.
const resetConfirmation = "reset"

// openAuthDB opens the same auth.db that serve holds open. Every command
// here is safe against a running server: authdb transactions take the write
// lock up front and wait on busy_timeout, and the server reads owner and
// client state from the database on each request, never from a cache.
func openAuthDB(cfg config.Config, stderr io.Writer) (*sql.DB, bool) {
	db, err := authdb.Open(filepath.Join(cfg.StateDir, "auth.db"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return db, true
}

// setup creates the owner (spec 6.1) and prints the three factors once, on
// stdout only: the TOTP URI, ten recovery codes, and a passkey enrollment
// link. The passkey step needs a browser, so it happens on the running
// server; the link carries its one-time token in the fragment, out of proxy
// logs. force replaces an existing owner's factors (Store.ReplaceOwner);
// passkeyOnly only issues another enrollment link.
func setup(cfg config.Config, passkeyOnly, force bool, stdout, stderr io.Writer) int {
	db, ok := openAuthDB(cfg, stderr)
	if !ok {
		return 1
	}
	defer func() { _ = db.Close() }()
	st := oauth.NewStore(db, time.Now)
	base := strings.TrimSuffix(cfg.PublicURL, "/")
	if passkeyOnly {
		token, expires, err := st.NewEnrollment()
		if errors.Is(err, oauth.ErrNotSetUp) {
			fmt.Fprintln(stderr, "setup -passkey: the owner is not set up yet; run cortex-mcp setup first")
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "setup:", err)
			return 1
		}
		printEnrollment(stdout, base, token, expires)
		return 0
	}
	u, err := url.Parse(base)
	if err != nil {
		fmt.Fprintln(stderr, "setup:", err)
		return 1
	}
	create := st.Setup
	if force {
		create = st.ReplaceOwner
	}
	sec, err := create(u.Hostname())
	if errors.Is(err, oauth.ErrAlreadySetUp) {
		fmt.Fprintln(stderr, "setup: already set up. Add a passkey with: cortex-mcp setup -passkey. "+
			"Replace every factor (the current ones stop working) with: cortex-mcp setup -force. "+
			"Also disconnect every OAuth client with: cortex-mcp reset-auth")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup:", err)
		return 1
	}
	fmt.Fprintf(stdout, "1. Authenticator app (TOTP). Add this URI, or type the secret by hand:\n   %s\n   secret: %s\n\n", sec.TOTPURI, sec.TOTPSecret)
	fmt.Fprintln(stdout, "2. Recovery codes. Each works once. Keep them offline, apart from the authenticator:")
	for _, c := range sec.RecoveryCodes {
		fmt.Fprintln(stdout, "   "+c)
	}
	fmt.Fprintln(stdout)
	printEnrollment(stdout, base, sec.EnrollToken, sec.EnrollExpires)
	fmt.Fprintln(stderr, "These secrets are shown only once. Keep the three factors in different places (passkey in a password manager, TOTP in an authenticator app, recovery codes offline).")
	if sec.Replaced {
		fmt.Fprintln(stderr, "The previous passkeys, authenticator entry and recovery codes no longer work, and logins they approved that had not yet connected were dropped. Connected OAuth clients stay connected; disconnect them with cortex-mcp clients revoke or cortex-mcp reset-auth.")
	}
	if !cfg.OAuth.Enabled {
		fmt.Fprintln(stderr, "warning: oauth.enabled is false in the config; assistants cannot connect through OAuth until it is true.")
	}
	return 0
}

func printEnrollment(w io.Writer, base, token string, expires time.Time) {
	fmt.Fprintf(w, "3. Passkey. With the server running, open this link before %s (single use) and enter a current authenticator code:\n   %s/enroll#%s\n",
		expires.UTC().Format(time.RFC3339), base, token)
}

// resetAuth is the last resort when factors are lost or stolen; it needs
// shell access on the host by construction. Without -yes it reads the
// word "reset" from stdin (so docker compose exec needs a TTY, or -yes), so a mistyped command cannot wipe the owner; a
// closed or non-interactive stdin is a refusal.
func resetAuth(cfg config.Config, yes bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if !yes {
		fmt.Fprintf(stderr, "reset-auth deletes the owner's passkeys, TOTP secret and recovery codes, and disconnects every OAuth client. Bearer tokens are kept.\nType %q to confirm (or run with -yes): ", resetConfirmation)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != resetConfirmation {
			fmt.Fprintln(stderr, "\nreset-auth: not confirmed; nothing changed. Type the word or pass -yes.")
			return 1
		}
	}
	db, ok := openAuthDB(cfg, stderr)
	if !ok {
		return 1
	}
	defer func() { _ = db.Close() }()
	if err := oauth.NewStore(db, time.Now).ResetAuth(); err != nil {
		fmt.Fprintln(stderr, "reset-auth:", err)
		return 1
	}
	fmt.Fprintln(stdout, "OAuth state cleared: the owner's credentials and every OAuth client are gone. Bearer tokens were kept. Run cortex-mcp setup to set up the owner again.")
	if !cfg.BearerTokens {
		fmt.Fprintln(stderr, "warning: bearer_tokens is false, so no client can authenticate until cortex-mcp setup runs again; serve refuses to start until then.")
	}
	return 0
}

// unlockTOTP clears the TOTP failure lock from the host, so the owner does
// not have to spend a recovery code after mistyping (or after someone else
// guessing) authenticator codes.
func unlockTOTP(cfg config.Config, stdout, stderr io.Writer) int {
	db, ok := openAuthDB(cfg, stderr)
	if !ok {
		return 1
	}
	defer func() { _ = db.Close() }()
	n, err := oauth.NewStore(db, time.Now).UnlockTOTP()
	if errors.Is(err, oauth.ErrNotSetUp) {
		fmt.Fprintln(stderr, "unlock-totp: the owner is not set up yet; run cortex-mcp setup first")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "unlock-totp:", err)
		return 1
	}
	if n == 0 {
		fmt.Fprintln(stdout, "Authenticator codes were not locked; nothing to clear.")
		return 0
	}
	fmt.Fprintf(stdout, "Authenticator codes unlocked: cleared %d failed attempt(s). If you did not make them, someone is guessing codes: consider cortex-mcp setup -force.\n", n)
	return 0
}

// clients lists or revokes Bearer tokens and OAuth clients (spec 6.4).
func clients(sub string, args []string, stdout, stderr io.Writer) int {
	nargs, ok := map[string]int{"list": 0, "revoke": 1}[sub]
	if !ok {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p := parse("clients "+sub, args, nargs, stdout, stderr)
	if p.done {
		return p.code
	}
	db, ok := openAuthDB(p.cfg, stderr)
	if !ok {
		return 1
	}
	defer func() { _ = db.Close() }()
	toks, st := tokens.New(db), oauth.NewStore(db, time.Now)
	if sub == "list" {
		return listClients(toks, st, stdout, stderr)
	}
	return revokeClient(toks, st, p.rest[0], stdout, stderr)
}

// listClients prints one tab-separated line per credential, Bearer tokens
// first: type, id, name, kind, then labelled fields. A Bearer token's id is
// its name. The kind of a CIMD client carries the host serving its metadata
// document, which is what identifies it; for every OAuth client the
// redirect hosts show where its codes can go.
func listClients(toks *tokens.Store, st *oauth.Store, stdout, stderr io.Writer) int {
	recs, err := toks.List()
	if err != nil {
		fmt.Fprintln(stderr, "clients list:", err)
		return 1
	}
	cls, err := st.ListClients()
	if err != nil {
		fmt.Fprintln(stderr, "clients list:", err)
		return 1
	}
	for _, r := range recs {
		fmt.Fprintf(stdout, "token\t%s\t%s\tbearer\tcreated %s\tlast used %s\n", r.Name, r.Name, r.Created.Format(time.RFC3339), lastUsed(r.LastUsed))
	}
	for _, c := range cls {
		kind := c.Kind
		if u, err := url.Parse(c.ID); err == nil && c.Kind == "cimd" {
			kind += " " + u.Hostname()
		}
		hosts := strings.Join(c.RedirectHosts, ",")
		if hosts == "" {
			hosts = "none"
		}
		fmt.Fprintf(stdout, "oauth\t%s\t%s\t%s\tcreated %s\tlast used %s\tconnections %d\tredirects %s\n",
			cell(c.ID), cell(c.Name), cell(kind), c.Created.Format(time.RFC3339), lastUsed(c.LastUsed), c.Grants, cell(hosts))
	}
	return 0
}

// cell keeps a value on one line and one column, and keeps terminal escape
// sequences out of the owner's terminal. Stored client data is already
// cleaned on the way in; this is the second line of defence for output.
func cell(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// revokeClient revokes exactly one credential. Ids come first and are
// never ambiguous: a Bearer token's name is its id, an OAuth client has a
// DCR id (uppercase base32) or a CIMD id (a URL), and token names are
// lowercase, so the id spaces cannot collide. Only when no id matches is the
// argument taken as an OAuth client's display name. Display names are
// chosen by whoever registered the client and need not be unique, so they
// never shadow an id (a client registering itself as "laptop" cannot block
// revoking the token "laptop"), and a name that matches more than one
// client is refused.
func revokeClient(toks *tokens.Store, st *oauth.Store, arg string, stdout, stderr io.Writer) int {
	cls, err := st.ListClients()
	if err != nil {
		fmt.Fprintln(stderr, "clients revoke:", err)
		return 1
	}
	var byName []oauth.ClientRecord
	for _, c := range cls {
		if c.ID == arg {
			return revokeOAuth(st, c, stdout, stderr)
		}
		if c.Name == arg {
			byName = append(byName, c)
		}
	}
	err = toks.Revoke(arg)
	if err == nil {
		fmt.Fprintln(stdout, "revoked Bearer token", arg)
		return 0
	}
	if !errors.Is(err, tokens.ErrNotFound) {
		fmt.Fprintln(stderr, "clients revoke:", err)
		return 1
	}
	switch len(byName) {
	case 0:
		fmt.Fprintf(stderr, "clients revoke: no Bearer token or OAuth client has the id or name %q (see cortex-mcp clients list)\n", cell(arg))
		return 1
	case 1:
		return revokeOAuth(st, byName[0], stdout, stderr)
	default:
		ids := make([]string, len(byName))
		for i, c := range byName {
			ids[i] = cell(c.ID)
		}
		fmt.Fprintf(stderr, "clients revoke: %q is the name of %d OAuth clients (%s). Nothing was revoked; run cortex-mcp clients list and revoke one by its id.\n",
			cell(arg), len(byName), strings.Join(ids, ", "))
		return 1
	}
}

func revokeOAuth(st *oauth.Store, c oauth.ClientRecord, stdout, stderr io.Writer) int {
	if err := st.RevokeClient(c.ID); errors.Is(err, oauth.ErrNotFound) {
		// Revoked by another command between the lookup and now.
		fmt.Fprintf(stderr, "clients revoke: no Bearer token or OAuth client has the id %q (see cortex-mcp clients list)\n", cell(c.ID))
		return 1
	} else if err != nil {
		fmt.Fprintln(stderr, "clients revoke:", err)
		return 1
	}
	fmt.Fprintf(stdout, "revoked OAuth client %s (%s)\n", cell(c.ID), cell(c.Name))
	return 0
}

func lastUsed(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}
