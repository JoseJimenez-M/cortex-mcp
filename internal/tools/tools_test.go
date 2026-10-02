package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

type env struct {
	cs          *mcp.ClientSession
	dir, logDir string
}

func connect(t *testing.T) env {
	t.Helper()
	dir, logDir := t.TempDir(), t.TempDir()
	v, err := vault.New(dir, vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lg, err := logs.Open(logDir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(s, Deps{Vault: v, Log: lg, LogDir: logDir, Now: time.Now})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
		_ = lg.Close()
		_ = v.Close()
	})
	return env{cs: cs, dir: dir, logDir: logDir}
}

func call(t *testing.T, e env, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func decode(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

func TestAllToolsAreListed(t *testing.T) {
	e := connect(t)
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	want := []string{"append", "backlinks", "create_note", "delete_note", "list", "move_note", "read_note", "recent", "replace_section", "search", "search_tag", "update_frontmatter"}
	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v", names)
	}
}

func TestCreateReadAppendReplaceFlow(t *testing.T) {
	e := connect(t)
	var v VersionOut
	decode(t, call(t, e, "create_note", map[string]any{"path": "Inbox/a.md", "content": "---\nstatus: draft\n---\n# Tasks\n- one\n"}), &v)
	decode(t, call(t, e, "append", map[string]any{"path": "Inbox/a.md", "section": "Tasks", "text": "- two"}), &v)
	var n NoteOut
	decode(t, call(t, e, "read_note", map[string]any{"path": "Inbox/a.md"}), &n)
	if !strings.Contains(n.Content, "- one\n- two\n") || n.Frontmatter["status"] != "draft" || n.Version != v.Version {
		t.Fatalf("note = %+v, last version %q", n, v.Version)
	}
	decode(t, call(t, e, "update_frontmatter", map[string]any{"path": "Inbox/a.md", "fields": map[string]any{"status": "active"}, "version": n.Version}), &v)
	decode(t, call(t, e, "replace_section", map[string]any{"path": "Inbox/a.md", "heading": "Tasks", "content": "- done", "version": v.Version}), &v)
	b, _ := os.ReadFile(filepath.Join(e.dir, "Inbox", "a.md"))
	if string(b) != "---\nstatus: active\n---\n# Tasks\n- done\n" {
		t.Fatalf("file = %q", b)
	}
}

func TestErrorsAreToolErrorsWithCodes(t *testing.T) {
	e := connect(t)
	cases := []struct {
		tool string
		args map[string]any
		code string
	}{
		{"read_note", map[string]any{"path": "../x.md"}, "path_outside_vault"},
		{"read_note", map[string]any{"path": "missing.md"}, "note_not_found"},
		{"replace_section", map[string]any{"path": "missing.md", "heading": "A", "content": "x", "version": "v"}, "note_not_found"},
		{"search", map[string]any{"query": " "}, "invalid_input"},
	}
	for _, c := range cases {
		res := call(t, e, c.tool, c.args)
		if !res.IsError || !strings.HasPrefix(text(res), c.code) {
			t.Errorf("%s %v: IsError=%v text=%q, want code %s", c.tool, c.args, res.IsError, text(res), c.code)
		}
	}
}

func TestInternalErrorsHideDetails(t *testing.T) {
	err := toolErr("read_note", errors.New("open /home/someone/vault/a.md: permission denied"))
	if strings.Contains(err.Error(), "/home") || !strings.HasPrefix(err.Error(), "internal_error") {
		t.Fatalf("toolErr leaked: %v", err)
	}
}

func TestWritesAreLoggedEvenWhenRejected(t *testing.T) {
	e := connect(t)
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": "x"})
	call(t, e, "create_note", map[string]any{"path": "../evil.md", "content": "x"})
	got, err := logs.ReadSince(e.logDir, time.Time{})
	if err != nil || len(got) != 2 {
		t.Fatalf("log = %+v, %v", got, err)
	}
	if got[0].Tool != "create_note" || got[0].Result != "ok" || got[0].Client != "unknown" || got[1].Result != "path_outside_vault" {
		t.Fatalf("log = %+v", got)
	}
}

func TestMoveDeleteSearchTagBacklinksRecent(t *testing.T) {
	e := connect(t)
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": "---\ntags: [topic/dev]\n---\nGo notes\n"})
	call(t, e, "create_note", map[string]any{"path": "b.md", "content": "see [[a]]\n"})

	var hits SearchOut
	decode(t, call(t, e, "search", map[string]any{"query": "go"}), &hits)
	if len(hits.Hits) != 1 || hits.Hits[0].Path != "a.md" {
		t.Fatalf("search = %+v", hits)
	}
	var paths PathsOut
	decode(t, call(t, e, "search_tag", map[string]any{"tag": "topic/dev"}), &paths)
	if !slices.Equal(paths.Paths, []string{"a.md"}) {
		t.Fatalf("search_tag = %+v", paths)
	}
	decode(t, call(t, e, "backlinks", map[string]any{"path": "a.md"}), &paths)
	if !slices.Equal(paths.Paths, []string{"b.md"}) {
		t.Fatalf("backlinks = %+v", paths)
	}
	var recent RecentOut
	decode(t, call(t, e, "recent", map[string]any{"days": 1}), &recent)
	if len(recent.Notes) != 2 || !slices.Contains(recent.Notes[0].Clients, "unknown") {
		t.Fatalf("recent = %+v", recent)
	}
	var moved MoveOut
	decode(t, call(t, e, "move_note", map[string]any{"from": "a.md", "to": "Archive/a.md"}), &moved)
	if !slices.Equal(moved.StillLinking, []string{"b.md"}) || !moved.BacklinksComplete {
		t.Fatalf("move = %+v", moved)
	}
	var del DeleteOut
	decode(t, call(t, e, "delete_note", map[string]any{"path": "b.md"}), &del)
	if del.TrashPath != ".trash/b.md" {
		t.Fatalf("delete = %+v", del)
	}
	var list ListOut
	decode(t, call(t, e, "list", map[string]any{}), &list)
	if len(list.Entries) != 1 || list.Entries[0].Path != "Archive" || !list.Entries[0].Folder {
		t.Fatalf("list = %+v", list)
	}
}

func TestEmptyResultsAreArraysNotNull(t *testing.T) {
	e := connect(t)
	var paths PathsOut
	decode(t, call(t, e, "search_tag", map[string]any{"tag": "none"}), &paths)
	if paths.Paths == nil {
		t.Fatal("paths decoded as null")
	}
}
func TestToolAnnotations(t *testing.T) {
	e := connect(t)
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	reads := []string{"read_note", "list", "search", "search_tag", "backlinks", "recent"}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil {
			t.Errorf("%s: no annotations", tool.Name)
			continue
		}
		if a.ReadOnlyHint != slices.Contains(reads, tool.Name) {
			t.Errorf("%s: ReadOnlyHint = %v", tool.Name, a.ReadOnlyHint)
		}
		wantDestructive := tool.Name == "replace_section" || tool.Name == "delete_note"
		if !a.ReadOnlyHint && (a.DestructiveHint == nil || *a.DestructiveHint != wantDestructive) {
			t.Errorf("%s: DestructiveHint = %v, want %v", tool.Name, a.DestructiveHint, wantDestructive)
		}
	}
}

func TestClientName(t *testing.T) {
	if got := clientName(nil); got != "unknown" {
		t.Errorf("nil request: %q", got)
	}
	if got := clientName(&mcp.CallToolRequest{}); got != "unknown" {
		t.Errorf("nil extra: %q", got)
	}
	req := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{Extra: map[string]any{"client": "claude"}}}}
	if got := clientName(req); got != "claude" {
		t.Errorf("token client: %q", got)
	}
	req.Extra.TokenInfo.Extra = nil
	if got := clientName(req); got != "unknown" {
		t.Errorf("nil token extra: %q", got)
	}
}

func TestEmptyRequiredStringsAreInvalidInput(t *testing.T) {
	e := connect(t)
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"read_note", map[string]any{"path": ""}},
		{"backlinks", map[string]any{"path": ""}},
		{"search_tag", map[string]any{"tag": " "}},
		{"create_note", map[string]any{"path": "", "content": "x"}},
		{"append", map[string]any{"path": "", "text": "x"}},
		{"replace_section", map[string]any{"path": "a.md", "heading": "", "content": "x", "version": "v"}},
		{"update_frontmatter", map[string]any{"path": "", "fields": map[string]any{}, "version": "v"}},
		{"move_note", map[string]any{"from": "", "to": "b.md"}},
		{"move_note", map[string]any{"from": "a.md", "to": ""}},
		{"delete_note", map[string]any{"path": ""}},
	}
	for _, c := range cases {
		res := call(t, e, c.tool, c.args)
		if !res.IsError || !strings.HasPrefix(text(res), "invalid_input") {
			t.Errorf("%s %v: IsError=%v text=%q", c.tool, c.args, res.IsError, text(res))
		}
	}
}

func TestResultsAreCapped(t *testing.T) {
	e := connect(t)
	for i := range maxResults + 5 {
		name := filepath.Join(e.dir, fmt.Sprintf("n%04d.md", i))
		if err := os.WriteFile(name, []byte("#tag [[target]]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(e.dir, "target.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var paths PathsOut
	decode(t, call(t, e, "search_tag", map[string]any{"tag": "tag"}), &paths)
	if len(paths.Paths) != maxResults || !paths.Truncated {
		t.Errorf("search_tag: %d paths, truncated=%v", len(paths.Paths), paths.Truncated)
	}
	paths = PathsOut{}
	decode(t, call(t, e, "backlinks", map[string]any{"path": "target.md"}), &paths)
	if len(paths.Paths) != maxResults || !paths.Truncated {
		t.Errorf("backlinks: %d paths, truncated=%v", len(paths.Paths), paths.Truncated)
	}
	var recent RecentOut
	decode(t, call(t, e, "recent", map[string]any{"days": 1}), &recent)
	if len(recent.Notes) != maxResults || !recent.Truncated {
		t.Errorf("recent: %d notes, truncated=%v", len(recent.Notes), recent.Truncated)
	}
	var list ListOut
	decode(t, call(t, e, "list", map[string]any{"recursive": true}), &list)
	if len(list.Entries) != maxResults || !list.Truncated {
		t.Errorf("list: %d entries, truncated=%v", len(list.Entries), list.Truncated)
	}
}

func TestSmallResultsAreNotMarkedTruncated(t *testing.T) {
	e := connect(t)
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": "x"})
	var list ListOut
	decode(t, call(t, e, "list", map[string]any{}), &list)
	if list.Truncated {
		t.Fatal("truncated set on a small list")
	}
}

func TestSearchLimitIsClamped(t *testing.T) {
	e := connect(t)
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": strings.Repeat("needle\n", 150)})
	var hits SearchOut
	decode(t, call(t, e, "search", map[string]any{"query": "needle", "limit": 1000}), &hits)
	if len(hits.Hits) != 100 {
		t.Errorf("limit 1000: %d hits, want 100", len(hits.Hits))
	}
	decode(t, call(t, e, "search", map[string]any{"query": "needle"}), &hits)
	if len(hits.Hits) != 20 {
		t.Errorf("default limit: %d hits, want 20", len(hits.Hits))
	}
	decode(t, call(t, e, "search", map[string]any{"query": "needle", "limit": -3}), &hits)
	if len(hits.Hits) != 20 {
		t.Errorf("negative limit: %d hits, want 20", len(hits.Hits))
	}
}

func TestFailingLogDoesNotFailTheTool(t *testing.T) {
	dir, logDir := t.TempDir(), t.TempDir()
	v, err := vault.New(dir, vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v.Close() }()
	lg, err := logs.Open(logDir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = lg.Close() // every Write now fails
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(s, Deps{Vault: v, Log: lg, LogDir: logDir})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "t"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "create_note", Arguments: map[string]any{"path": "a.md", "content": "x"}})
	if err != nil || res.IsError {
		t.Fatalf("create_note with a broken log: %v %v", err, res)
	}
}

func TestMoveReportsBacklinkScanState(t *testing.T) {
	e := connect(t)
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": "x"})
	var moved MoveOut
	decode(t, call(t, e, "move_note", map[string]any{"from": "a.md", "to": "b.md"}), &moved)
	if moved.StillLinking == nil || !moved.BacklinksComplete {
		t.Fatalf("move = %+v", moved)
	}
	got, _ := logs.ReadSince(e.logDir, time.Time{})
	if got[len(got)-1].Path != "a.md -> b.md" {
		t.Fatalf("log path = %q", got[len(got)-1].Path)
	}
}

func TestReadNoteWithRichFrontmatterPassesOutputSchema(t *testing.T) {
	e := connect(t)
	src := "---\ncreated: 2026-01-02\ntags: [a, b]\nnested:\n  k: 1\n---\nbody\n"
	call(t, e, "create_note", map[string]any{"path": "a.md", "content": src})
	var n NoteOut
	decode(t, call(t, e, "read_note", map[string]any{"path": "a.md"}), &n)
	if n.Frontmatter["nested"] == nil || n.Frontmatter["tags"] == nil {
		t.Fatalf("note = %+v", n)
	}
}
