//go:build unix

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendPreservesFileMode(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "p.md", "a\n")
	full := filepath.Join(dir, "p.md")
	if err := os.Chmod(full, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Append("p.md", "b"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(full)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}
