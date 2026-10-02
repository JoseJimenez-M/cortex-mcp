package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestVault(t *testing.T, opts Options) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := New(dir, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Fatalf("error = %v (code %q), want code %q", err, got, code)
	}
}

func TestNewRejectsMissingFolder(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing"), Options{}); err == nil {
		t.Fatal("New on a missing folder: expected an error")
	}
}

func TestErrorFormatAndCodeOf(t *testing.T) {
	err := errf(CodeNotFound, "%s does not exist", "a.md")
	if err.Error() != "note_not_found: a.md does not exist" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if CodeOf(os.ErrClosed) != "" {
		t.Fatal("CodeOf on a non-vault error must be empty")
	}
}

func TestNewRejectsInvalidDenyEntries(t *testing.T) {
	for _, d := range []string{"Priv\x00ate", "a/ b", "x \u202e", "bad\\name", "\xff", "a/\u200b"} {
		_, err := New(t.TempDir(), Options{Deny: []string{"ok", d}})
		if err == nil || !strings.Contains(err.Error(), "deny entry") {
			t.Errorf("New with deny %q: err = %v, want an error naming the entry", d, err)
		}
	}
	if _, err := New(t.TempDir(), Options{Deny: []string{"Private/", "Work/secret.md", "año"}}); err != nil {
		t.Errorf("valid deny entries rejected: %v", err)
	}
}

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
