package vault

import (
	"strings"
	"testing"
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
		{"a\x00b.md", accessRead, true, CodePathOutside},
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
	for _, s := range []string{"a.md", "../a.md", "a/../../b.md", "/x.md", ".git/x.md", "a//b/./c.md", "\x00", ".trash/../.git/x"} {
		f.Add(s)
	}
	v, err := New(f.TempDir(), Options{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, err := v.clean(in, accessWrite, false)
		if err != nil {
			return
		}
		if p != "." && (strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../")) {
			t.Fatalf("clean(%q) = %q escapes the vault", in, p)
		}
		switch strings.SplitN(p, "/", 2)[0] {
		case ".git", ".obsidian", ".cortex-mcp", ".trash":
			t.Fatalf("clean(%q) = %q reached a protected folder for writing", in, p)
		}
	})
}
