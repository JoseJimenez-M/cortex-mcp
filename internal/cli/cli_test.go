package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, "vault")
	if err := os.Mkdir(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("vault: %s\nstate_dir: %s\npublic_url: http://localhost:8080\n", vaultDir, filepath.Join(dir, "state"))
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
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
