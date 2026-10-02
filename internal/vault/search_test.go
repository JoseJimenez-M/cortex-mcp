package vault

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, "a.md", "---\ntags: [topic/dev, kind/note]\n---\nSee [[Lib/b]] and #idea here.\n")
	writeFile(t, dir, "Lib/b.md", "# B\nGo is fun\nlink to [a](../a.md)\n")
	writeFile(t, dir, "Lib/c.txt", "Go text file")
	writeFile(t, dir, "Lib/d.md", "[[b|alias]] mention of go\n")
	writeFile(t, dir, ".obsidian/x.md", "Go hidden")
	writeFile(t, dir, ".trash/old.md", "Go trashed [[Lib/b]]")
	writeFile(t, dir, "Private/p.md", "Go private")
	return v, dir
}

func TestList(t *testing.T) {
	v, _ := fixture(t)
	got, err := v.List("", false)
	if err != nil || !slices.Equal(got, []Entry{{"Lib", true}, {"a.md", false}}) {
		t.Fatalf("List root = %+v, %v", got, err)
	}
	got, err = v.List(".", true)
	if err != nil || !slices.Equal(got, []Entry{{"Lib/b.md", false}, {"Lib/d.md", false}, {"a.md", false}}) {
		t.Fatalf("List recursive = %+v, %v", got, err)
	}
	got, err = v.List(".trash", false)
	if err != nil || !slices.Equal(got, []Entry{{".trash/old.md", false}}) {
		t.Fatalf("List .trash = %+v, %v", got, err)
	}
	_, err = v.List("Private", false)
	wantCode(t, err, CodePathProtected)
	_, err = v.List("a.md", false)
	wantCode(t, err, CodeInvalidPath)
	_, err = v.List("nope", false)
	wantCode(t, err, CodeNotFound)
}

func TestSearch(t *testing.T) {
	v, _ := fixture(t)
	got, err := v.Search("go", "", 0)
	want := []Hit{{"Lib/b.md", 2, "Go is fun"}, {"Lib/d.md", 1, "[[b|alias]] mention of go"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("Search = %+v, %v", got, err)
	}
	got, _ = v.Search("go", "Lib", 1)
	if len(got) != 1 {
		t.Fatalf("limit 1 returned %d hits", len(got))
	}
	_, err = v.Search("  ", "", 0)
	wantCode(t, err, CodeInvalidInput)
}

func TestSearchTag(t *testing.T) {
	v, _ := fixture(t)
	for _, tag := range []string{"topic/dev", "kind/note", "#idea"} {
		got, err := v.SearchTag(tag)
		if err != nil || !slices.Equal(got, []string{"a.md"}) {
			t.Errorf("SearchTag(%q) = %v, %v", tag, got, err)
		}
	}
	if got, _ := v.SearchTag("nothing"); len(got) != 0 {
		t.Errorf("SearchTag(nothing) = %v", got)
	}
}

func TestBacklinks(t *testing.T) {
	v, _ := fixture(t)
	got, err := v.Backlinks("Lib/b.md")
	if err != nil || !slices.Equal(got, []string{"Lib/d.md", "a.md"}) {
		t.Fatalf("Backlinks(Lib/b.md) = %v, %v", got, err)
	}
	got, err = v.Backlinks("a.md")
	if err != nil || !slices.Equal(got, []string{"Lib/b.md"}) {
		t.Fatalf("Backlinks(a.md) = %v, %v", got, err)
	}
}

func TestRecent(t *testing.T) {
	v, dir := fixture(t)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "a.md"), old, old); err != nil {
		t.Fatal(err)
	}
	got, err := v.Recent(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range got {
		paths = append(paths, r.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"Lib/b.md", "Lib/d.md"}) {
		t.Fatalf("Recent = %v", paths)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Modified.After(got[i-1].Modified) {
			t.Fatal("Recent is not sorted newest first")
		}
	}
}

func listPaths(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Path)
	}
	return out
}

func TestProtectedNeverExposed(t *testing.T) {
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, "ok.md", "needle #tagx [[Lib/target]]\n")
	writeFile(t, dir, "Lib/target.md", "needle\n")
	for _, p := range []string{
		"Repo/.git/HEAD.md", "Sub/.Obsidian/x.md", "PRIVATE/p.md",
		".trash/a/.git/z.md", ".CORTEX-MCP/m.md",
	} {
		writeFile(t, dir, p, "needle #tagx [[Lib/target]]\n")
	}
	bad := func(p string) bool {
		return v.protectedErr(p, accessRead) != nil || (isTrash(p) && p != "")
	}
	for _, rec := range []bool{true, false} {
		for _, f := range []string{".", "Repo", "Sub", "Lib"} {
			es, err := v.List(f, rec)
			if err != nil {
				t.Fatalf("List(%q): %v", f, err)
			}
			for _, p := range listPaths(es) {
				if bad(p) {
					t.Errorf("List(%q, %v) exposed %s", f, rec, p)
				}
			}
		}
	}
	check := func(name string, paths []string) {
		for _, p := range paths {
			if bad(p) {
				t.Errorf("%s exposed %s", name, p)
			}
		}
	}
	hits, _ := v.Search("needle", "", 100)
	var hp []string
	for _, h := range hits {
		hp = append(hp, h.Path)
	}
	check("Search", hp)
	if !slices.Equal(hp, []string{"Lib/target.md", "ok.md"}) {
		t.Errorf("Search = %v", hp)
	}
	tg, _ := v.SearchTag("tagx")
	check("SearchTag", tg)
	if !slices.Equal(tg, []string{"ok.md"}) {
		t.Errorf("SearchTag = %v", tg)
	}
	rc, _ := v.Recent(time.Now().Add(-time.Hour))
	var rp []string
	for _, r := range rc {
		rp = append(rp, r.Path)
	}
	check("Recent", rp)
	if len(rp) != 2 {
		t.Errorf("Recent = %v", rp)
	}
	bl, _ := v.Backlinks("Lib/target.md")
	check("Backlinks", bl)
	if !slices.Equal(bl, []string{"ok.md"}) {
		t.Errorf("Backlinks = %v", bl)
	}
}

func TestTrashListingKeepsProtectedHidden(t *testing.T) {
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, ".trash/ok.md", "x")
	writeFile(t, dir, ".trash/a/.git/z.md", "x")
	writeFile(t, dir, ".trash/a/b.md", "x")
	es, err := v.List(".trash", true)
	if err != nil || !slices.Equal(listPaths(es), []string{".trash/a/b.md", ".trash/ok.md"}) {
		t.Fatalf("List .trash recursive = %v, %v", es, err)
	}
	es, err = v.List(".trash/a", false)
	if err != nil || !slices.Equal(listPaths(es), []string{".trash/a/b.md"}) {
		t.Fatalf("List .trash/a = %v, %v", es, err)
	}
	hits, _ := v.Search("x", ".trash", 0)
	if len(hits) != 2 {
		t.Fatalf("Search .trash = %v", hits)
	}
}

func TestListTrailingSlashAndCase(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "Lib/b.md", "x")
	es, err := v.List("Lib/", false)
	if err != nil || !slices.Equal(es, []Entry{{"Lib/b.md", false}}) {
		t.Fatalf("List Lib/ = %v, %v", es, err)
	}
}

func TestSearchCRLFAndOrdering(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "z.md", "first\r\nHello World\r\n")
	writeFile(t, dir, "a.md", "ÁRBOL here\r\n")
	got, err := v.Search("hello", "", 0)
	if err != nil || !slices.Equal(got, []Hit{{"z.md", 2, "Hello World"}}) {
		t.Fatalf("Search = %+v, %v", got, err)
	}
	got, _ = v.Search("árbol", "", 0)
	if !slices.Equal(got, []Hit{{"a.md", 1, "ÁRBOL here"}}) {
		t.Fatalf("non-ASCII Search = %+v", got)
	}
	for i := range 120 {
		writeFile(t, dir, "many/n"+string(rune('a'+i%26))+string(rune('a'+i/26))+".md", "hit\n")
	}
	got, _ = v.Search("hit", "", 1000)
	if len(got) != 100 {
		t.Fatalf("cap: got %d hits", len(got))
	}
	if !slices.IsSortedFunc(got, func(a, b Hit) int { return strings.Compare(a.Path, b.Path) }) {
		t.Fatal("hits are not in lexical order")
	}
}

func TestBacklinkForms(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "My Note.md", "x")
	writeFile(t, dir, "h.md", "[[My Note#Heading]]")
	writeFile(t, dir, "b.md", "[[My Note^blk]]")
	writeFile(t, dir, "al.md", "[[My Note|shown]]")
	writeFile(t, dir, "md.md", "[x](My%20Note.md)")
	writeFile(t, dir, "md2.md", "[x](My%20Note.md#sec)")
	writeFile(t, dir, "ext.md", "[x](https://example.com/My%20Note.md)")
	writeFile(t, dir, "none.md", "[[Other]]")
	writeFile(t, dir, "sub/rel.md", "[x](../My%20Note.md)")
	got, err := v.Backlinks("My Note.md")
	want := []string{"al.md", "b.md", "h.md", "md.md", "md2.md", "sub/rel.md"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("Backlinks = %v, %v", got, err)
	}
	_, err = v.Backlinks("../x.md")
	wantCode(t, err, CodePathOutside)
}

func TestSymlinkedOutsideNotesNotExposed(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.md"), []byte("needle"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "in.md", "needle")
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(dir, "linkfile.md")); err != nil {
		t.Fatal(err)
	}
	es, err := v.List(".", true)
	if err != nil || !slices.Equal(listPaths(es), []string{"in.md"}) {
		t.Fatalf("List = %v, %v", es, err)
	}
	hits, _ := v.Search("needle", "", 0)
	if len(hits) != 1 || hits[0].Path != "in.md" {
		t.Fatalf("Search = %+v", hits)
	}
	rc, _ := v.Recent(time.Now().Add(-time.Hour))
	if len(rc) != 1 {
		t.Fatalf("Recent = %+v", rc)
	}
	_, err = v.List("linkdir", true)
	if err == nil {
		t.Fatal("List of a symlinked outside folder succeeded")
	}
}
