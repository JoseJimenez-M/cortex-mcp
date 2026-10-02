package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestCreateWritesNewNoteInNewFolders(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	ver, err := v.Create("Library/Inbox/idea.md", "# Idea\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "Library/Inbox/idea.md"); got != "# Idea\n" {
		t.Fatalf("content = %q", got)
	}
	n, err := v.Read("Library/Inbox/idea.md")
	if err != nil || n.Version != ver {
		t.Fatalf("Read version = %v, %v; want %q", n, err, ver)
	}
}

func TestCreateRefusesExistingNote(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "original")
	_, err := v.Create("a.md", "new")
	wantCode(t, err, CodeExists)
	if got := readFile(t, dir, "a.md"); got != "original" {
		t.Fatalf("existing note was changed to %q", got)
	}
}

func TestCreateRefusesTrashAndOversizedWrites(t *testing.T) {
	v, _ := newTestVault(t, Options{MaxWriteBytes: 10})
	_, err := v.Create(".trash/x.md", "a")
	wantCode(t, err, CodePathProtected)
	_, err = v.Create("big.md", strings.Repeat("x", 11))
	wantCode(t, err, CodeTooLarge)
}

func TestAppendToEnd(t *testing.T) {
	cases := []struct{ content, text, want string }{
		{"", "b", "b\n"},
		{"a", "b", "a\nb\n"},
		{"a\n", "b\n\n", "a\nb\n"},
	}
	for _, c := range cases {
		if got := appendToEnd(c.content, c.text); got != c.want {
			t.Errorf("appendToEnd(%q, %q) = %q, want %q", c.content, c.text, got, c.want)
		}
	}
}

func TestAppendErrors(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	_, err := v.Append("missing.md", "x")
	wantCode(t, err, CodeNotFound)
	writeFile(t, dir, "a.md", "a\n")
	_, err = v.Append("a.md", "  \n")
	wantCode(t, err, CodeInvalidInput)
}

func TestConcurrentAppendsKeepEveryLine(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	if _, err := v.Create("log.md", ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Append("log.md", fmt.Sprintf("line %d", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(readFile(t, dir, "log.md"), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("got %d lines, want 50", len(lines))
	}
}

func TestWritesLeaveNoTempFiles(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	if _, err := v.Create("a/b.md", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Append("a/b.md", "y"); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".cortex-tmp-") {
			t.Errorf("temp file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteNewNeverOverwrites(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "original")
	err := v.writeNew("a.md", []byte("new"))
	wantCode(t, err, CodeExists)
	if got := readFile(t, dir, "a.md"); got != "original" {
		t.Fatalf("existing note was changed to %q", got)
	}
	if err := v.writeNew("sub/b.md", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "sub/b.md"); got != "fresh" {
		t.Fatalf("content = %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cortex-tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteAtomicFailureLeavesNoTempFile(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "d/keep.md", "x")
	// Renaming a file over a non-empty folder fails after the temp file exists.
	err := v.writeAtomic("d", []byte("y"))
	if err == nil {
		t.Fatal("expected an error")
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cortex-tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".cortex-tmp-") {
			t.Errorf("temp file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteNewFallbackWhenLinkUnsupported(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.link = func(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	if err := v.writeNew("sub/n.md", []byte("exact\n")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "sub/n.md"); got != "exact\n" {
		t.Fatalf("content = %q", got)
	}
	writeFile(t, dir, "e.md", "original")
	wantCode(t, v.writeNew("e.md", []byte("new")), CodeExists)
	if got := readFile(t, dir, "e.md"); got != "original" {
		t.Fatalf("existing note was changed to %q", got)
	}
	noTempFiles(t, dir)
}

func TestWriteNewOtherLinkErrorsAreReported(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.link = func(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.EIO} }
	if err := v.writeNew("n.md", []byte("x")); err == nil || !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want EIO", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "n.md")); err == nil {
		t.Fatal("note was created despite the error")
	}
	noTempFiles(t, dir)
}

func TestWriteNewConcurrentExactlyOneWins(t *testing.T) {
	for _, forceFallback := range []bool{false, true} {
		v, dir := newTestVault(t, Options{})
		if forceFallback {
			v.link = func(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.ENOTSUP} }
		}
		const n = 20
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = v.writeNew("race.md", []byte(fmt.Sprintf("payload %d", i)))
			}()
		}
		wg.Wait()
		winner := -1
		for i, err := range errs {
			if err == nil {
				if winner != -1 {
					t.Fatalf("fallback=%v: two writers succeeded", forceFallback)
				}
				winner = i
				continue
			}
			wantCode(t, err, CodeExists)
		}
		if winner == -1 {
			t.Fatalf("fallback=%v: no writer succeeded", forceFallback)
		}
		if got := readFile(t, dir, "race.md"); got != fmt.Sprintf("payload %d", winner) {
			t.Fatalf("fallback=%v: content = %q, winner %d", forceFallback, got, winner)
		}
		noTempFiles(t, dir)
	}
}

func TestLinkUnsupportedCoversErrUnsupported(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.link = func(_, _ string) error {
		return &os.LinkError{Op: "link", Err: fmt.Errorf("wrapped: %w", errors.ErrUnsupported)}
	}
	if err := v.writeNew("u.md", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "u.md"); got != "ok" {
		t.Fatalf("content = %q", got)
	}
}
