//go:build unix

package vault

import (
	"os"
	"path/filepath"
	"syscall"
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

// Not parallel: the umask is process-wide.
func TestCreateRespectsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	v, dir := newTestVault(t, Options{})
	if _, err := v.Create("m.md", "x"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "m.md"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestWritesRefuseSymlinks(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "real.md", "a\n")
	if err := os.Symlink("real.md", filepath.Join(dir, "link.md")); err != nil {
		t.Fatal(err)
	}
	_, err := v.Append("link.md", "b")
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Create("link.md", "b")
	wantCode(t, err, CodeInvalidPath)
	if err := os.Symlink(".", filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	_, err = v.Create("dirlink/new.md", "b")
	wantCode(t, err, CodeInvalidPath)
}
