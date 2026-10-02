package vault

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func TestCleanAcceptsVaultRelativePaths(t *testing.T) {
	v, _ := newTestVault(t, Options{Deny: []string{"Work/secret.md"}})
	cases := []struct {
		in   string
		a    access
		md   bool
		want string
	}{
		{"a.md", accessWrite, true, "a.md"},
		{"Library/Inbox/x.md", accessWrite, true, "Library/Inbox/x.md"},
		{"./Library/x.md", accessWrite, true, "Library/x.md"},
		{"Library//x.md", accessWrite, true, "Library/x.md"},
		{"Library/sub/../x.md", accessWrite, true, "Library/x.md"},
		{"Notes/UPPER.MD", accessWrite, true, "Notes/UPPER.MD"},
		{"Work/other.md", accessWrite, true, "Work/other.md"},
		{".trash/old.md", accessRead, true, ".trash/old.md"},
		{".trash/old.md", accessMoveFrom, true, ".trash/old.md"},
		{"", accessRead, false, "."},
		{".", accessRead, false, "."},
		{"./", accessRead, false, "."},
		{".//a.md", accessWrite, true, "a.md"},
		{"././a.md", accessWrite, true, "a.md"},
		{"././/a/b.md", accessWrite, true, "a/b.md"},
		{"a/.gitignore.md", accessWrite, true, "a/.gitignore.md"},
		{".trash/.GIT.md", accessRead, true, ".trash/.GIT.md"},
		{"x/.Trash/y.md", accessWrite, true, "x/.Trash/y.md"},
		{"Library", accessRead, false, "Library"},
	}
	for _, c := range cases {
		got, err := v.clean(c.in, c.a, c.md)
		if err != nil || got != c.want {
			t.Errorf("clean(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestCleanRejectsUnsafePaths(t *testing.T) {
	v, _ := newTestVault(t, Options{Deny: []string{"Private/", "Work/secret.md"}})
	cases := []struct {
		in   string
		a    access
		md   bool
		code Code
	}{
		{"", accessRead, true, CodeInvalidPath},
		{"../x.md", accessRead, true, CodePathOutside},
		{"a/../../x.md", accessRead, true, CodePathOutside},
		{"/etc/x.md", accessRead, true, CodePathOutside},
		{"a\x00b.md", accessRead, true, CodeInvalidPath},
		{"a\tb.md", accessRead, true, CodeInvalidPath},
		{"a\nb.md", accessRead, true, CodeInvalidPath},
		{"a\\b.md", accessRead, true, CodeInvalidPath},
		{"..\\x.md", accessRead, true, CodeInvalidPath},
		{"a.md ", accessRead, true, CodeInvalidPath},
		{" a.md", accessRead, true, CodeInvalidPath},
		{"a/ ", accessRead, false, CodeInvalidPath},
		{"a/.git/x.md", accessRead, true, CodePathProtected},
		{"Assistant/repo/.git", accessRead, false, CodePathProtected},
		{"x/.obsidian/y.md", accessWrite, true, CodePathProtected},
		{"a/b/.cortex-mcp/z.md", accessRead, true, CodePathProtected},
		{".GIT/x.md", accessRead, true, CodePathProtected},
		{".Obsidian/x.md", accessRead, true, CodePathProtected},
		{"a/.Cortex-MCP", accessRead, false, CodePathProtected},
		{".Trash/x.md", accessWrite, true, CodePathProtected},
		{"private/x.md", accessRead, true, CodePathProtected},
		{"work/SECRET.md", accessRead, true, CodePathProtected},
		{"note.txt", accessWrite, true, CodeNotMarkdown},
		{".git/config.md", accessRead, true, CodePathProtected},
		{".obsidian/app.md", accessRead, true, CodePathProtected},
		{".cortex-mcp/x.md", accessRead, true, CodePathProtected},
		{".git", accessRead, false, CodePathProtected},
		{".trash/x.md", accessWrite, true, CodePathProtected},
		{"Private/x.md", accessRead, true, CodePathProtected},
		{"Private", accessRead, false, CodePathProtected},
		{"Work/secret.md", accessRead, true, CodePathProtected},
	}
	for _, c := range cases {
		_, err := v.clean(c.in, c.a, c.md)
		if got := CodeOf(err); got != c.code {
			t.Errorf("clean(%q): code %q (%v), want %q", c.in, got, err, c.code)
		}
	}
}

func FuzzCleanNeverEscapes(f *testing.F) {
	seeds := []string{"a.md", "../a.md", "a/../../b.md", "/x.md", ".git/x.md", "a//b/./c.md", "\x00",
		".trash/../.git/x", "a/.git/x.md", ".GIT/x", ".//a.md", "././a.md", "a\\b.md", " a.md", "a/.Obsidian/b", ".Trash/x"}
	for _, s := range seeds {
		for m := uint8(0); m < 4; m++ {
			f.Add(s, m)
		}
	}
	v, err := New(f.TempDir(), Options{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in string, mode uint8) {
		a := access(mode % 3)
		wantMD := mode&4 != 0
		p, err := v.clean(in, a, wantMD)
		if err != nil || p == "." {
			return
		}
		if !filepath.IsLocal(filepath.FromSlash(p)) || path.Clean(p) != p {
			t.Fatalf("clean(%q) = %q is not a local canonical path", in, p)
		}
		if strings.ContainsFunc(p, func(r rune) bool { return unicode.IsControl(r) || r == '\\' }) {
			t.Fatalf("clean(%q) = %q contains a control character or backslash", in, p)
		}
		for i, seg := range strings.Split(p, "/") {
			for _, n := range neverAccessible {
				if strings.EqualFold(seg, n) {
					t.Fatalf("clean(%q) = %q reached protected %s", in, p, n)
				}
			}
			if i == 0 && a == accessWrite && strings.EqualFold(seg, trashDir) {
				t.Fatalf("clean(%q) = %q writes into the trash", in, p)
			}
		}
		if wantMD && !strings.EqualFold(path.Ext(p), ".md") {
			t.Fatalf("clean(%q) = %q is not markdown", in, p)
		}
	})
}

func TestFsErr(t *testing.T) {
	other := errors.New("boom")
	cases := []struct {
		name string
		err  error
		code Code
	}{
		{"not exist", fs.ErrNotExist, CodeNotFound},
		{"exist", fs.ErrExist, CodeExists},
	}
	for _, c := range cases {
		wantCode(t, fsErr(c.err, "a.md"), c.code)
	}
	if fsErr(nil, "a.md") != nil {
		t.Error("fsErr(nil) must be nil")
	}
	if got := fsErr(other, "a.md"); got != other {
		t.Errorf("unrelated error changed: %v", got)
	}
}

// TestFsErrMapsRootSymlinkEscape guards the stdlib error text that fsErr
// matches: os.Root must refuse a symlink leaving the vault with a message
// containing "path escapes from parent".
func TestFsErrMapsRootSymlinkEscape(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	outside := t.TempDir()
	writeFile(t, outside, "secret.md", "secret")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(dir, "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := v.root.Stat("link.md")
	if err == nil {
		t.Fatal("os.Root followed a symlink leaving the vault")
	}
	wantCode(t, fsErr(err, "link.md"), CodePathOutside)
}
