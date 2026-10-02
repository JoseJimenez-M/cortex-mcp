package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	wantCode(t, err, CodeInvalidPath)
}

func TestInVaultSymlinksAreNeverFollowed(t *testing.T) {
	v, dir := newTestVault(t, Options{Deny: []string{"Private"}})
	writeFile(t, dir, "Private/p.md", "needle #tagx")
	writeFile(t, dir, ".git/HEAD.md", "needle #tagx")
	writeFile(t, dir, "Real/n.md", "needle #tagx")
	writeFile(t, dir, "Lib/ok.md", "needle [[Real/n]]")
	links := map[string]string{
		"Lib/x.md":        "../Private/p.md",
		"Lib/gitlink":     "../.git",
		"Lib/privlink":    "../Private",
		"Alias":           "Real",
		"Lib/realnote.md": "../Real/n.md",
	}
	for l, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(l))); err != nil {
			t.Skip("symlinks unavailable:", err)
		}
	}
	for _, p := range []string{"Lib/x.md", "Lib/gitlink/HEAD.md", "Lib/privlink/p.md", "Alias/n.md", "Lib/realnote.md"} {
		_, err := v.Read(p)
		wantCode(t, err, CodeInvalidPath)
	}
	for _, f := range []string{"Lib/gitlink", "Alias", "Lib/privlink"} {
		_, err := v.List(f, false)
		wantCode(t, err, CodeInvalidPath)
		_, err = v.Search("needle", f, 0)
		wantCode(t, err, CodeInvalidPath)
	}
	es, err := v.List(".", true)
	if err != nil || !slices.Equal(listPaths(es), []string{"Lib/ok.md", "Real/n.md"}) {
		t.Fatalf("List recursive = %v, %v", es, err)
	}
	es, _ = v.List("Lib", false)
	if !slices.Equal(listPaths(es), []string{"Lib/ok.md"}) {
		t.Fatalf("List Lib = %v", es)
	}
	hits, _ := v.Search("needle", "", 0)
	if len(hits) != 2 {
		t.Fatalf("Search = %+v", hits)
	}
	tg, _ := v.SearchTag("tagx")
	if !slices.Equal(tg, []string{"Real/n.md"}) {
		t.Fatalf("SearchTag = %v", tg)
	}
	rc, _ := v.Recent(time.Now().Add(-time.Hour))
	if len(rc) != 2 {
		t.Fatalf("Recent = %+v", rc)
	}
	bl, _ := v.Backlinks("Real/n.md")
	if !slices.Equal(bl, []string{"Lib/ok.md"}) {
		t.Fatalf("Backlinks = %v", bl)
	}
	_, err = v.Backlinks("Alias/n.md")
	wantCode(t, err, CodeInvalidPath)
}

func TestSnippetShowsMatchOnHugeLine(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "big.md", strings.Repeat("é", 1_000_000)+" the NEEDLE here"+strings.Repeat("x", 5000))
	hits, err := v.Search("needle", "", 0)
	if err != nil || len(hits) != 1 {
		t.Fatalf("Search = %+v, %v", hits, err)
	}
	s := hits[0].Snippet
	if !strings.Contains(s, "NEEDLE") || !strings.HasPrefix(s, "...") || !strings.HasSuffix(s, "...") {
		t.Fatalf("snippet = %q", s)
	}
	if n := len([]rune(s)); n > 206 {
		t.Fatalf("snippet has %d runes", n)
	}
}

func TestRecentTiesKeepLexicalOrder(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	same := time.Now().Add(-time.Minute)
	var want []string
	for i := range 60 {
		p := fmt.Sprintf("n%02d.md", i)
		writeFile(t, dir, p, "x")
		if err := os.Chtimes(filepath.Join(dir, p), same, same); err != nil {
			t.Fatal(err)
		}
		want = append(want, p)
	}
	got, err := v.Recent(same.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range got {
		paths = append(paths, r.Path)
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("Recent order = %v", paths)
	}
}

func TestSearchFolderMustBeFolder(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "needle")
	_, err := v.Search("needle", "a.md", 0)
	wantCode(t, err, CodeInvalidPath)
	_, err = v.Search("needle", "nope", 0)
	wantCode(t, err, CodeNotFound)
}

func TestWalksSkipPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs an unprivileged unix user")
	}
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "needle")
	writeFile(t, dir, "locked/b.md", "needle")
	locked := filepath.Join(dir, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	hits, err := v.Search("needle", "", 0)
	if err != nil || len(hits) != 1 || hits[0].Path != "a.md" {
		t.Fatalf("Search = %+v, %v", hits, err)
	}
	if _, err := v.Recent(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("Recent: %v", err)
	}
}

func TestScansSkipUnreadableNotes(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs an unprivileged unix user")
	}
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "good.md", "needle #tagx [[target]]")
	writeFile(t, dir, "bad.md", "needle #tagx [[target]]")
	writeFile(t, dir, "target.md", "x")
	if err := os.Chmod(filepath.Join(dir, "bad.md"), 0); err != nil {
		t.Fatal(err)
	}
	hits, err := v.Search("needle", "", 0)
	if err != nil || len(hits) != 1 || hits[0].Path != "good.md" {
		t.Fatalf("Search = %+v, %v", hits, err)
	}
	tg, err := v.SearchTag("tagx")
	if err != nil || !slices.Equal(tg, []string{"good.md"}) {
		t.Fatalf("SearchTag = %v, %v", tg, err)
	}
	bl, err := v.Backlinks("target.md")
	if err != nil || !slices.Equal(bl, []string{"good.md"}) {
		t.Fatalf("Backlinks = %v, %v", bl, err)
	}
}

func TestSnippetNoEllipsisForTrailingWhitespace(t *testing.T) {
	line := "needle" + strings.Repeat("a", 194) + "   \r"
	if s := snippet(line, 0); strings.HasSuffix(s, "...") {
		t.Fatalf("snippet = %q", s)
	}
	if s := snippet(line+"more", 0); !strings.HasSuffix(s, "...") {
		t.Fatalf("snippet = %q", s)
	}
}

func TestNewestFirstKeepsTiesStable(t *testing.T) {
	base := time.Now()
	in := []RecentNote{
		{"d", base}, {"b", base.Add(time.Hour)}, {"a", base}, {"e", base.Add(time.Hour)}, {"c", base},
	}
	// Pre-sort lexically as a walk would deliver them.
	slices.SortFunc(in, func(a, b RecentNote) int { return strings.Compare(a.Path, b.Path) })
	slices.SortStableFunc(in, newestFirst)
	var got []string
	for _, r := range in {
		got = append(got, r.Path)
	}
	if !slices.Equal(got, []string{"b", "e", "a", "c", "d"}) {
		t.Fatalf("order = %v", got)
	}
}
