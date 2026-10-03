package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

func writeConfig(t *testing.T) string { return writeConfigExtra(t, "") }

// writeConfigExtra writes a valid config plus extra YAML lines.
func writeConfigExtra(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, "vault")
	if err := os.Mkdir(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("vault: %s\nstate_dir: %s\npublic_url: http://localhost:8080\n%s", vaultDir, filepath.Join(dir, "state"), extra)
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(args ...string) (int, string, string) { return runIn("", args...) }

// runIn runs a command with stdin as its standard input.
func runIn(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestTokenLifecycle(t *testing.T) {
	cfg := writeConfig(t)
	code, out, errOut := run("token", "create", "-config", cfg, "muse")
	if code != 0 || !strings.HasPrefix(out, "cmcp_") || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") || !strings.Contains(errOut, "shown only once") {
		t.Fatalf("create: %d %q %q", code, out, errOut)
	}
	if strings.Contains(errOut, strings.TrimSpace(out)) {
		t.Fatal("secret leaked to stderr")
	}
	code, out, _ = run("token", "list", "-config", cfg)
	if code != 0 || !strings.HasPrefix(out, "muse\tcreated ") || !strings.Contains(out, "last used never") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, out, _ = run("token", "revoke", "-config", cfg, "muse")
	if code != 0 || out != "revoked muse\n" {
		t.Fatalf("revoke: %d %q", code, out)
	}
	code, _, errOut = run("token", "revoke", "-config", cfg, "muse")
	if code != 1 || !strings.Contains(errOut, "not found") {
		t.Fatalf("second revoke: %d %q", code, errOut)
	}
}

func TestTokenCreateErrors(t *testing.T) {
	cfg := writeConfig(t)
	if code, _, _ := run("token", "create", "-config", cfg, "muse"); code != 0 {
		t.Fatal("first create failed")
	}
	code, out, errOut := run("token", "create", "-config", cfg, "muse")
	if code != 1 || out != "" || errOut == "" {
		t.Fatalf("duplicate: %d %q %q", code, out, errOut)
	}
	code, out, _ = run("token", "create", "-config", cfg, "bad name!")
	if code != 1 || out != "" {
		t.Fatalf("bad name: %d %q", code, out)
	}
}

func TestConfigFromEnvironment(t *testing.T) {
	t.Setenv("CORTEX_MCP_CONFIG", writeConfig(t))
	if code, _, errOut := run("token", "list"); code != 0 {
		t.Fatalf("list with env config: %d %q", code, errOut)
	}
}

func TestFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("CORTEX_MCP_CONFIG", "/nonexistent.yaml")
	if code, _, errOut := run("token", "list", "-config", writeConfig(t)); code != 0 {
		t.Fatalf("flag should win: %d %q", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		nil, {"bogus"}, {"token"}, {"token", "bogus"}, {"token", "create"},
		{"token", "list", "extra"}, {"token", "revoke"}, {"version", "extra"},
		{"serve", "extra"}, {"serve", "-nosuchflag"},
		{"clients"}, {"clients", "bogus"}, {"clients", "revoke"}, {"clients", "list", "extra"},
		{"setup", "extra"}, {"setup", "-passkey", "-force"}, {"reset-auth", "extra"}, {"unlock-totp", "extra"},
	}
	for _, args := range cases {
		if code, _, errOut := run(args...); code != 2 || errOut == "" {
			t.Errorf("Run(%v) = %d (stderr %q), want 2 with a message", args, code, errOut)
		}
	}
}

func TestFlagsAfterNameGiveHint(t *testing.T) {
	code, _, errOut := run("token", "create", "muse", "-config", "x.yaml")
	if code != 2 || !strings.Contains(errOut, "flags must come before") {
		t.Fatalf("got %d %q", code, errOut)
	}
}

func TestMissingConfigIsFailure(t *testing.T) {
	for _, args := range [][]string{
		{"token", "list", "-config", "/nonexistent.yaml"},
		{"serve", "-config", "/nonexistent.yaml"},
	} {
		if code, _, errOut := run(args...); code != 1 || errOut == "" {
			t.Errorf("Run(%v) = %d %q, want 1", args, code, errOut)
		}
	}
}

func TestHelp(t *testing.T) {
	for _, a := range []string{"-h", "--help", "help"} {
		code, out, errOut := run(a)
		if code != 0 || !strings.Contains(out, "Usage:") || errOut != "" {
			t.Errorf("%s: %d %q %q", a, code, out, errOut)
		}
	}
	code, out, _ := run("token", "list", "-h")
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("token list -h: %d %q", code, out)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || !strings.HasPrefix(out, "cortex-mcp ") || !strings.HasSuffix(out, "\n") {
		t.Fatalf("version: %d %q", code, out)
	}
}

var enrollExpiry = regexp.MustCompile(`before \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)

var recoveryLine = regexp.MustCompile(`(?m)^   [A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)

// execAuthDB runs SQL against the config's auth.db, as a test fixture.
func execAuthDB(t *testing.T, cfgPath string, stmts ...string) {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := authdb.Open(filepath.Join(cfg.StateDir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupPrintsTheThreeFactorsOnce(t *testing.T) {
	cfg := writeConfig(t)
	code, out, errOut := run("setup", "-config", cfg)
	if code != 0 {
		t.Fatalf("setup: %d %s", code, errOut)
	}
	if !strings.Contains(out, "otpauth://totp/cortex-mcp:localhost?") || len(recoveryLine.FindAllString(out, -1)) != 10 ||
		!strings.Contains(out, "http://localhost:8080/enroll#") || !strings.Contains(errOut, "shown only once") ||
		!enrollExpiry.MatchString(out) {
		t.Fatalf("setup output (stdout withheld: it holds secrets): %d recovery lines, expiry %v\n%s",
			len(recoveryLine.FindAllString(out, -1)), enrollExpiry.MatchString(out), errOut)
	}
	for _, c := range recoveryLine.FindAllString(out, -1) {
		if strings.Contains(errOut, strings.TrimSpace(c)) {
			t.Fatal("a recovery code reached stderr")
		}
	}
	code, out, errOut = run("setup", "-config", cfg)
	if code != 1 || !strings.Contains(errOut, "already set up") || !strings.Contains(errOut, "-force") || out != "" {
		t.Fatalf("second setup: %d %q %q", code, out, errOut)
	}
}

func TestSetupForceReplacesTheFactors(t *testing.T) {
	cfg := writeConfig(t)
	// Without an owner -force is a plain setup: nothing was replaced.
	if code, _, errOut := run("setup", "-config", cfg, "-force"); code != 0 || strings.Contains(errOut, "no longer work") {
		t.Fatalf("setup -force without owner: %d %q", code, errOut)
	}
	_, first, _ := run("setup", "-config", cfg, "-force")
	code, out, errOut := run("setup", "-config", cfg, "-force")
	if code != 0 || len(recoveryLine.FindAllString(out, -1)) != 10 || !strings.Contains(errOut, "no longer work") ||
		!strings.Contains(errOut, "approved") {
		t.Fatalf("setup -force: %d (stdout withheld) %q", code, errOut)
	}
	if recoveryLine.FindString(first) == recoveryLine.FindString(out) {
		t.Fatal("setup -force printed the old recovery codes")
	}
}

func TestSetupPasskeyIssuesANewLink(t *testing.T) {
	cfg := writeConfig(t)
	if code, _, errOut := run("setup", "-config", cfg, "-passkey"); code != 1 || !strings.Contains(errOut, "not set up") {
		t.Fatalf("setup -passkey before setup: %d %q", code, errOut)
	}
	if code, _, _ := run("setup", "-config", cfg); code != 0 {
		t.Fatal("setup failed")
	}
	code, out, _ := run("setup", "-config", cfg, "-passkey")
	if code != 0 || !strings.Contains(out, "http://localhost:8080/enroll#") || strings.Contains(out, "otpauth://") || !enrollExpiry.MatchString(out) {
		t.Fatalf("setup -passkey: %d (stdout withheld: it holds the link token)", code)
	}
}

func TestResetAuthNeedsConfirmation(t *testing.T) {
	cfg := writeConfig(t)
	_, _, _ = run("setup", "-config", cfg)
	for _, in := range []string{"", "no\n", "RESET-ish\n"} {
		if code, _, errOut := runIn(in, "reset-auth", "-config", cfg); code != 1 || !strings.Contains(errOut, "-yes") {
			t.Fatalf("reset-auth with input %q: %d %q", in, code, errOut)
		}
	}
	if code, _, errOut := run("setup", "-config", cfg); code != 1 {
		t.Fatalf("an unconfirmed reset-auth changed state: %d %q", code, errOut)
	}
	if code, out, errOut := runIn("reset\n", "reset-auth", "-config", cfg); code != 0 || !strings.Contains(out, "cortex-mcp setup") {
		t.Fatalf("reset-auth confirmed by typing: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := run("setup", "-config", cfg); code != 0 {
		t.Fatalf("setup after reset: %d %q", code, errOut)
	}
	if code, out, _ := run("reset-auth", "-config", cfg, "-yes"); code != 0 || !strings.Contains(out, "cortex-mcp setup") {
		t.Fatalf("reset-auth -yes: %d %q", code, out)
	}
}

func TestResetAuthWarnsWhenBearerTokensAreOff(t *testing.T) {
	cfg := writeConfigExtra(t, "bearer_tokens: false\n")
	_, _, _ = run("setup", "-config", cfg)
	code, _, errOut := run("reset-auth", "-config", cfg, "-yes")
	if code != 0 || !strings.Contains(errOut, "bearer_tokens is false") {
		t.Fatalf("reset-auth with bearer_tokens false: %d %q", code, errOut)
	}
	if _, _, errOut := run("reset-auth", "-config", writeConfig(t), "-yes"); strings.Contains(errOut, "bearer_tokens") {
		t.Fatalf("warned with bearer_tokens on: %q", errOut)
	}
}

func TestResetAuthKeepsBearerTokens(t *testing.T) {
	cfg := writeConfig(t)
	if code, _, _ := run("token", "create", "-config", cfg, "laptop"); code != 0 {
		t.Fatal("token create failed")
	}
	_, _, _ = run("setup", "-config", cfg)
	execAuthDB(t, cfg, `INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('CLIENTONE', 'dcr', 'Claude', '[]', 1)`)
	if code, _, _ := run("reset-auth", "-config", cfg, "-yes"); code != 0 {
		t.Fatal("reset-auth failed")
	}
	code, out, _ := run("clients", "list", "-config", cfg)
	if code != 0 || !strings.Contains(out, "token\tlaptop\t") || strings.Contains(out, "CLIENTONE") {
		t.Fatalf("clients list after reset-auth: %d\n%s", code, out)
	}
}

func TestUnlockTOTP(t *testing.T) {
	cfg := writeConfig(t)
	if code, _, errOut := run("unlock-totp", "-config", cfg); code != 1 || !strings.Contains(errOut, "not set up") {
		t.Fatalf("unlock-totp before setup: %d %q", code, errOut)
	}
	_, _, _ = run("setup", "-config", cfg)
	execAuthDB(t, cfg, `UPDATE owner SET totp_failures = 5`)
	if code, out, _ := run("unlock-totp", "-config", cfg); code != 0 || !strings.Contains(out, "cleared 5 failed") {
		t.Fatalf("unlock-totp: %d %q", code, out)
	}
	if code, out, _ := run("unlock-totp", "-config", cfg); code != 0 || !strings.Contains(out, "not locked") {
		t.Fatalf("unlock-totp again: %d %q", code, out)
	}
}

func TestClientsListAndRevoke(t *testing.T) {
	cfgPath := writeConfig(t)
	if code, _, _ := run("token", "create", "-config", cfgPath, "laptop"); code != 0 {
		t.Fatal("token create failed")
	}
	execAuthDB(t, cfgPath,
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('CLIENTONE', 'dcr', 'Claude', '["https://claude.ai/api/mcp/auth_callback"]', 1)`,
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('https://app.example.com/oauth/meta.json', 'cimd', 'App', '["https://app.example.com/cb"]', 2)`,
		`INSERT INTO grants(family, client_id, scopes, audience, amr, auth_time, created, last_used) VALUES('fam', 'CLIENTONE', '[]', '', 'otp', 1, 1, 1700000000)`)
	code, out, _ := run("clients", "list", "-config", cfgPath)
	if code != 0 || !strings.Contains(out, "token\tlaptop\tlaptop\tbearer\t") ||
		!strings.Contains(out, "oauth\tCLIENTONE\tClaude\tdcr\t") || !strings.Contains(out, "redirects claude.ai") ||
		!strings.Contains(out, "connections 1") || !strings.Contains(out, "last used 2023-11-14T22:13:20Z") ||
		!strings.Contains(out, "\tcimd app.example.com\t") {
		t.Fatalf("clients list: %d\n%s", code, out)
	}
	if code, out, _ := run("clients", "revoke", "-config", cfgPath, "laptop"); code != 0 || !strings.Contains(out, "revoked Bearer token laptop") {
		t.Fatalf("revoke token: %d %q", code, out)
	}
	if code, out, _ := run("clients", "revoke", "-config", cfgPath, "CLIENTONE"); code != 0 || !strings.Contains(out, "revoked OAuth client CLIENTONE") {
		t.Fatalf("revoke client: %d %q", code, out)
	}
	if code, _, errOut := run("clients", "revoke", "-config", cfgPath, "CLIENTONE"); code != 1 || !strings.Contains(errOut, "no Bearer token or OAuth client") {
		t.Fatalf("revoke twice: %d %q", code, errOut)
	}
	if code, out, _ := run("clients", "revoke", "-config", cfgPath, "App"); code != 0 || !strings.Contains(out, "revoked OAuth client https://app.example.com/oauth/meta.json (App)") {
		t.Fatalf("revoke by name: %d %q", code, out)
	}
	if code, out, _ := run("clients", "list", "-config", cfgPath); code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("list after revoking everything: %d %q", code, out)
	}
}

func TestClientsRevokeRefusesAmbiguousNames(t *testing.T) {
	cfg := writeConfig(t)
	if code, _, _ := run("token", "create", "-config", cfg, "claude"); code != 0 {
		t.Fatal("token create failed")
	}
	execAuthDB(t, cfg,
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('AAAA', 'dcr', 'Claude', '[]', 1)`,
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('BBBB', 'dcr', 'Claude', '[]', 2)`,
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('CCCC', 'dcr', 'claude', '[]', 3)`)
	code, out, errOut := run("clients", "revoke", "-config", cfg, "Claude")
	if code != 1 || out != "" || !strings.Contains(errOut, "AAAA") || !strings.Contains(errOut, "BBBB") || !strings.Contains(errOut, "clients list") {
		t.Fatalf("ambiguous client name: %d %q %q", code, out, errOut)
	}
	// A Bearer token name is an id. CCCC (a self-registered client anyone
	// could have named "claude") must not block revoking the token.
	if code, out, errOut := run("clients", "revoke", "-config", cfg, "claude"); code != 0 || !strings.Contains(out, "revoked Bearer token claude") {
		t.Fatalf("revoke Bearer token by name: %d %q %q", code, out, errOut)
	}
	// An OAuth client id is never ambiguous either.
	if code, out, _ := run("clients", "revoke", "-config", cfg, "AAAA"); code != 0 || !strings.Contains(out, "revoked OAuth client AAAA") {
		t.Fatalf("revoke by id: %d %q", code, out)
	}
	_, out, _ = run("clients", "list", "-config", cfg)
	if strings.Count(out, "\n") != 2 || !strings.Contains(out, "BBBB") || !strings.Contains(out, "CCCC") {
		t.Fatalf("revokes touched the wrong credentials:\n%s", out)
	}
	// With the token gone, "claude" names one OAuth client only.
	if code, out, _ := run("clients", "revoke", "-config", cfg, "claude"); code != 0 || !strings.Contains(out, "revoked OAuth client CCCC") {
		t.Fatalf("revoke by unique display name: %d %q", code, out)
	}
}

func TestClientsListSanitizesNames(t *testing.T) {
	cfg := writeConfig(t)
	execAuthDB(t, cfg, "INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('EVIL', 'dcr', 'a\x1b[31m\tb\nc', '[]', 1)")
	_, out, _ := run("clients", "list", "-config", cfg)
	if strings.ContainsAny(out, "\x1b") || strings.Count(out, "\n") != 1 || !strings.Contains(out, "\tEVIL\ta[31m b c\t") {
		t.Fatalf("clients list printed a raw name: %q", out)
	}
}
