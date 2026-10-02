package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadReturnsContentFrontmatterAndVersion(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "Library/a.md", "---\ntype: note\ncreated: 2026-10-01\ntags: [topic/dev]\n---\n# A\nbody\n")
	n, err := v.Read("Library/a.md")
	if err != nil {
		t.Fatal(err)
	}
	if n.Path != "Library/a.md" || !strings.Contains(n.Content, "body") {
		t.Fatalf("unexpected note %+v", n)
	}
	// Dates stay strings: yaml.v3 keeps timestamp-like values as strings
	// when decoding into interface{}, which is what JSON clients expect.
	if n.Frontmatter["type"] != "note" || n.Frontmatter["created"] != "2026-10-01" {
		t.Fatalf("frontmatter = %#v", n.Frontmatter)
	}
	if len(n.Version) != 16 {
		t.Fatalf("version %q, want 16 hex chars", n.Version)
	}
	writeFile(t, dir, "Library/a.md", "changed\n")
	n2, err := v.Read("Library/a.md")
	if err != nil {
		t.Fatal(err)
	}
	if n2.Version == n.Version {
		t.Fatal("version did not change with the content")
	}
	if n2.Frontmatter != nil {
		t.Fatalf("expected no frontmatter, got %#v", n2.Frontmatter)
	}
}

func TestReadMissingNote(t *testing.T) {
	v, _ := newTestVault(t, Options{})
	_, err := v.Read("nope.md")
	wantCode(t, err, CodeNotFound)
}

func TestReadFolderIsInvalid(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "x.md/inner.md", "a")
	_, err := v.Read("x.md")
	wantCode(t, err, CodeInvalidPath)
}

func TestReadKeepsNoteWhenFrontmatterIsBroken(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "b.md", "---\ntype: [\n---\nbody\n")
	n, err := v.Read("b.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n.FrontmatterError, "frontmatter_invalid") || n.Content != "---\ntype: [\n---\nbody\n" {
		t.Fatalf("note = %+v", n)
	}
}

func TestReadRefusesSymlinksLeavingTheVault(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	outside := t.TempDir()
	writeFile(t, outside, "secret.md", "secret")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(dir, "link.md")); err != nil {
		t.Skip("symlinks not supported here:", err)
	}
	_, err := v.Read("link.md")
	wantCode(t, err, CodePathOutside)
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	_, err = v.Read("out/secret.md")
	wantCode(t, err, CodePathOutside)
}
