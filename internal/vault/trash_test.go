package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func exists(dir, rel string) bool {
	_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
	return err == nil
}

func TestMoveReportsBacklinksAndDoesNotRewriteThem(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "A")
	writeFile(t, dir, "b.md", "see [[a]]")
	still, complete, err := v.Move("a.md", "Archive/a.md")
	if err != nil {
		t.Fatal(err)
	}
	if exists(dir, "a.md") || !exists(dir, "Archive/a.md") {
		t.Fatal("note was not moved")
	}
	if !complete || !slices.Equal(still, []string{"b.md"}) || readFile(t, dir, "b.md") != "see [[a]]" {
		t.Fatalf("still linking = %v, b.md = %q", still, readFile(t, dir, "b.md"))
	}
	noTempFiles(t, dir)
}

func TestMoveErrors(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "A")
	writeFile(t, dir, "b.md", "B")
	writeFile(t, dir, "Folder.md/x.md", "X")
	_, _, err := v.Move("a.md", "b.md")
	wantCode(t, err, CodeExists)
	_, _, err = v.Move("missing.md", "c.md")
	wantCode(t, err, CodeNotFound)
	_, _, err = v.Move("a.md", ".trash/a.md")
	wantCode(t, err, CodePathProtected)
	_, _, err = v.Move("a.md", "a.md")
	wantCode(t, err, CodeInvalidInput)
	_, _, err = v.Move("Folder.md", "c.md")
	wantCode(t, err, CodeInvalidPath)
	_, _, err = v.Move("../a.md", "c.md")
	wantCode(t, err, CodePathOutside)
	_, _, err = v.Move("a.md", ".git/a.md")
	wantCode(t, err, CodePathProtected)
	if readFile(t, dir, "a.md") != "A" || readFile(t, dir, "b.md") != "B" {
		t.Fatal("a failed move changed a note")
	}
}

func TestMovePreservesContentExactly(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	content := "---\r\ntitle: x\r\n---\nbody no trailing newline \xff"
	writeFile(t, dir, "a.md", content)
	if _, _, err := v.Move("a.md", "x/y/a.md"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "x/y/a.md"); got != content {
		t.Fatalf("content changed: %q", got)
	}
	noTempFiles(t, dir)
}

func TestRestoreFromTrash(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, ".trash/old.md", "old")
	if _, _, err := v.Move(".trash/old.md", "old.md"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dir, "old.md") != "old" || exists(dir, ".trash/old.md") {
		t.Fatal("restore failed")
	}
}

func TestDeleteMovesToTrashAndAvoidsClashes(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.now = func() time.Time { return time.Date(2026, 10, 2, 15, 4, 5, 0, time.UTC) }
	writeFile(t, dir, "Lib/b.md", "first")
	got, err := v.Delete("Lib/b.md")
	if err != nil || got != ".trash/Lib/b.md" || exists(dir, "Lib/b.md") || readFile(t, dir, ".trash/Lib/b.md") != "first" {
		t.Fatalf("Delete = %q, %v", got, err)
	}
	writeFile(t, dir, "Lib/b.md", "second")
	got, err = v.Delete("Lib/b.md")
	if err != nil || got != ".trash/Lib/b.20261002T150405.md" || readFile(t, dir, got) != "second" {
		t.Fatalf("second Delete = %q, %v", got, err)
	}
	_, err = v.Delete("missing.md")
	wantCode(t, err, CodeNotFound)
	_, err = v.Delete(".trash/Lib/b.md")
	wantCode(t, err, CodePathProtected)
	noTempFiles(t, dir)
}

func TestDeleteSameSecondGetsCounter(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.now = func() time.Time { return time.Date(2026, 10, 2, 15, 4, 5, 0, time.UTC) }
	want := []string{".trash/c.md", ".trash/c.20261002T150405.md", ".trash/c.20261002T150405-2.md", ".trash/c.20261002T150405-3.md"}
	for i, w := range want {
		writeFile(t, dir, "c.md", fmt.Sprintf("v%d", i))
		got, err := v.Delete("c.md")
		if err != nil || got != w {
			t.Fatalf("Delete #%d = %q, %v, want %q", i, got, err, w)
		}
	}
	for i, w := range want {
		if got := readFile(t, dir, w); got != fmt.Sprintf("v%d", i) {
			t.Fatalf("%s = %q", w, got)
		}
	}
}

func noLink(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }

func TestMoveAndDeleteFallbackWithoutHardLinks(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	v.link = noLink
	writeFile(t, dir, "a.md", "A")
	writeFile(t, dir, "b.md", "B")
	if _, _, err := v.Move("a.md", "x/a.md"); err != nil {
		t.Fatal(err)
	}
	if exists(dir, "a.md") || readFile(t, dir, "x/a.md") != "A" {
		t.Fatal("fallback move failed")
	}
	_, _, err := v.Move("b.md", "x/a.md")
	wantCode(t, err, CodeExists)
	if got, err := v.Delete("b.md"); err != nil || got != ".trash/b.md" || readFile(t, dir, got) != "B" {
		t.Fatalf("Delete = %q, %v", got, err)
	}
}

func TestMoveDoesNotClobberTargetCreatedAfterCheck(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "A")
	// Simulate an external process creating the target between the
	// existence check and the publish.
	v.link = func(old, nw string) error {
		if err := os.WriteFile(filepath.Join(dir, nw), []byte("external"), 0o644); err != nil {
			t.Fatal(err)
		}
		return os.Link(filepath.Join(dir, old), filepath.Join(dir, nw))
	}
	_, _, err := v.Move("a.md", "t.md")
	wantCode(t, err, CodeExists)
	if readFile(t, dir, "t.md") != "external" || readFile(t, dir, "a.md") != "A" {
		t.Fatal("racing target was clobbered or source lost")
	}
}

func TestMoveOtherLinkErrorIsReported(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "A")
	v.link = func(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.EIO} }
	if _, _, err := v.Move("a.md", "b.md"); err == nil || !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want EIO", err)
	}
	if readFile(t, dir, "a.md") != "A" || exists(dir, "b.md") {
		t.Fatal("failed move changed the vault")
	}
}

func TestMoveConcurrentExactlyOneWins(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	const n = 10
	for i := range n {
		writeFile(t, dir, fmt.Sprintf("s%d.md", i), fmt.Sprintf("n%d", i))
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = v.Move(fmt.Sprintf("s%d.md", i), "dst.md")
		}()
	}
	wg.Wait()
	wins := 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
			if readFile(t, dir, "dst.md") != fmt.Sprintf("n%d", i) {
				t.Fatalf("dst has the wrong content for winner %d", i)
			}
		default:
			wantCode(t, err, CodeExists)
			if !exists(dir, fmt.Sprintf("s%d.md", i)) {
				t.Fatalf("loser %d lost its note", i)
			}
		}
	}
	if wins != 1 {
		t.Fatalf("%d moves won, want 1", wins)
	}
}

func TestMoveBacklinkScanFailureStillReportsSuccess(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "A")
	v.backlinks = func(string) ([]string, error) { return []string{"junk.md"}, errors.New("walk failed") }
	still, complete, err := v.Move("a.md", "b.md")
	if err != nil || complete || still != nil {
		t.Fatalf("Move = %v, %v, %v; want nil, false, nil", still, complete, err)
	}
	if exists(dir, "a.md") || readFile(t, dir, "b.md") != "A" {
		t.Fatal("the move did not happen")
	}
}

func TestMoveDenyFolderAndBadPaths(t *testing.T) {
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, "a.md", "A")
	writeFile(t, dir, "Private/s.md", "S")
	_, _, err := v.Move("a.md", "Private/a.md")
	wantCode(t, err, CodePathProtected)
	_, _, err = v.Move("Private/s.md", "s.md")
	wantCode(t, err, CodePathProtected)
	_, err = v.Delete("Private/s.md")
	wantCode(t, err, CodePathProtected)
	for _, bad := range []string{"../x.md", "/abs/x.md", "x\x00.md"} {
		_, _, err = v.Move("a.md", bad)
		if c := CodeOf(err); c != CodePathOutside && c != CodeInvalidPath {
			t.Fatalf("Move target %q: %v", bad, err)
		}
		_, err = v.Delete(bad)
		if c := CodeOf(err); c != CodePathOutside && c != CodeInvalidPath {
			t.Fatalf("Delete %q: %v", bad, err)
		}
	}
	if !exists(dir, "a.md") || !exists(dir, "Private/s.md") {
		t.Fatal("a refused operation changed the vault")
	}
}

func TestRestoreFromTrashReportsBacklinks(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, ".trash/old.md", "old")
	writeFile(t, dir, "b.md", "see [[old]]")
	still, complete, err := v.Move(".trash/old.md", "old.md")
	if err != nil || !complete || !slices.Equal(still, []string{"b.md"}) {
		t.Fatalf("Move = %v, %v, %v", still, complete, err)
	}
}

func TestReadOnlyFileIsReadableButNeverWritten(t *testing.T) {
	v, dir := newTestVault(t, Options{ReadOnly: []string{"Meta/AGENTS.md"}})
	const orig = "# Rules\nbe nice\n"
	writeFile(t, dir, "Meta/AGENTS.md", orig)
	writeFile(t, dir, "other.md", "o")
	n, err := v.Read("Meta/AGENTS.md")
	if err != nil || n.Content != orig {
		t.Fatalf("Read = %v, %v", n, err)
	}
	ver := n.Version
	for name, op := range map[string]func(p string) error{
		"Create":            func(p string) error { _, err := v.Create(p, "x"); return err },
		"Append":            func(p string) error { _, err := v.Append(p, "x"); return err },
		"AppendToSection":   func(p string) error { _, err := v.AppendToSection(p, "Rules", "x"); return err },
		"ReplaceSection":    func(p string) error { _, err := v.ReplaceSection(p, "Rules", "x", ver); return err },
		"UpdateFrontmatter": func(p string) error { _, err := v.UpdateFrontmatter(p, map[string]any{"a": 1}, ver); return err },
		"Delete":            func(p string) error { _, err := v.Delete(p); return err },
		"MoveFrom":          func(p string) error { _, _, err := v.Move(p, "moved.md"); return err },
		"MoveTo":            func(p string) error { _, _, err := v.Move("other.md", p); return err },
	} {
		for _, p := range []string{"Meta/AGENTS.md", "META/agents.MD", "./Meta//AGENTS.md"} {
			err := op(p)
			wantCode(t, err, CodePathProtected)
			if !strings.Contains(err.Error(), "is the server instructions file") {
				t.Errorf("%s(%q): message %q does not name the instructions file", name, p, err)
			}
		}
	}
	if readFile(t, dir, "Meta/AGENTS.md") != orig || !exists(dir, "other.md") {
		t.Fatal("a refused write changed the vault")
	}
}

func TestDenyAppliesInsideTrash(t *testing.T) {
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, ".trash/Private/x.md", "needle")
	writeFile(t, dir, ".trash/private/y.md", "needle")
	writeFile(t, dir, ".trash/Public/z.md", "needle")
	for _, p := range []string{".trash/Private/x.md", ".TRASH/private/y.md"} {
		_, err := v.Read(p)
		wantCode(t, err, CodePathProtected)
		_, _, err = v.Move(p, "restored.md")
		wantCode(t, err, CodePathProtected)
	}
	_, err := v.List(".trash/Private", false)
	wantCode(t, err, CodePathProtected)
	for _, rec := range []bool{true, false} {
		es, err := v.List(".trash", rec)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range listPaths(es) {
			if strings.Contains(strings.ToLower(p), "private") {
				t.Errorf("List(.trash, %v) exposed %s", rec, p)
			}
		}
	}
	hits, err := v.Search("needle", ".trash", 0)
	if err != nil || len(hits) != 1 || hits[0].Path != ".trash/Public/z.md" {
		t.Fatalf("Search .trash = %v, %v", hits, err)
	}
	if _, err := v.Read(".trash/Public/z.md"); err != nil {
		t.Fatalf("an undenied trashed note must stay readable: %v", err)
	}
}

func TestMoveRemoveFailureNeverLosesTheNote(t *testing.T) {
	eio := &os.PathError{Op: "remove", Path: "src", Err: syscall.EIO}
	cases := []struct {
		name string
		// during runs in place of removing the source after the link.
		during           func(t *testing.T, dir string) error
		wantErr          bool
		wantSrc, wantDst string // "" means absent
	}{
		{
			name: "source already gone: the move succeeded",
			during: func(t *testing.T, dir string) error {
				if err := os.Remove(filepath.Join(dir, "a.md")); err != nil {
					t.Fatal(err)
				}
				return &os.PathError{Op: "remove", Path: "a.md", Err: fs.ErrNotExist}
			},
			wantDst: "A",
		},
		{
			name:    "remove fails, same file: roll back",
			during:  func(*testing.T, string) error { return eio },
			wantErr: true, wantSrc: "A",
		},
		{
			name: "remove fails, source rewritten meanwhile: keep both",
			during: func(t *testing.T, dir string) error {
				tmp := filepath.Join(dir, ".ext-tmp")
				if err := os.WriteFile(tmp, []byte("NEW"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, filepath.Join(dir, "a.md")); err != nil {
					t.Fatal(err)
				}
				return eio
			},
			wantErr: true, wantSrc: "NEW", wantDst: "A",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, dir := newTestVault(t, Options{})
			writeFile(t, dir, "a.md", "A")
			v.remove = func(string) error { return c.during(t, dir) }
			_, _, err := v.Move("a.md", "b.md")
			if (err != nil) != c.wantErr {
				t.Fatalf("Move err = %v, want error %v", err, c.wantErr)
			}
			for rel, want := range map[string]string{"a.md": c.wantSrc, "b.md": c.wantDst} {
				if want == "" {
					if exists(dir, rel) {
						t.Errorf("%s exists, want absent", rel)
					}
				} else if !exists(dir, rel) || readFile(t, dir, rel) != want {
					t.Errorf("%s missing or wrong, want %q", rel, want)
				}
			}
		})
	}
}
