package vault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		if strings.HasPrefix(d.Name(), ".cortex-tmp-") {
			t.Errorf("temp file left behind: %s", p)
		}
		return err
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
