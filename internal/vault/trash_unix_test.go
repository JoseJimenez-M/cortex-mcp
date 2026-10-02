//go:build unix

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMovePreservesMode(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "p.md", "secret")
	if err := os.Chmod(filepath.Join(dir, "p.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Move("p.md", "q/p.md"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "q", "p.md"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
}

func TestMoveAndDeleteRefuseSymlinks(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	outside := t.TempDir()
	writeFile(t, dir, "real.md", "R")
	writeFile(t, dir, "Dest/keep.md", "K")
	if err := os.Symlink("real.md", filepath.Join(dir, "link.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Dest", filepath.Join(dir, "destlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".trash")); err != nil {
		t.Fatal(err)
	}
	// Source is a symlinked note, source passes through a symlinked folder,
	// target passes through a symlinked folder.
	_, err := v.Move("link.md", "moved.md")
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Move("destlink/keep.md", "moved.md")
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Move("real.md", "destlink/real.md")
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Move("real.md", "out/real.md")
	wantCode(t, err, CodeInvalidPath)
	// Deleting a symlinked note, and deleting when .trash is a symlink.
	_, err = v.Delete("link.md")
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Delete("real.md")
	wantCode(t, err, CodeInvalidPath)

	if !exists(dir, "real.md") || !exists(dir, "link.md") || exists(dir, "moved.md") || exists(dir, "Dest/real.md") {
		t.Fatal("a refused operation changed the vault")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("something was written outside the vault: %v", entries)
	}
}
