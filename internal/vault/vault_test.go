package vault

import (
	"os"
	"path/filepath"
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
