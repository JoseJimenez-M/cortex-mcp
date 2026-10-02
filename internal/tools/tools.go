// Package tools exposes the vault as MCP tools. Handlers are thin: they
// call the vault, log writes, and map errors. No file I/O happens here.
package tools

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JoseJimenez-M/cortex-mcp/internal/logs"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

// maxResults caps the entries of every tool that can list the whole vault,
// so one call cannot return megabytes into an assistant's context.
const maxResults = 500

// Search limits: the default and the ceiling a client may ask for.
const (
	defaultSearchLimit = 20
	maxSearchLimit     = 100
)

// Deps are what the tools need.
type Deps struct {
	Vault  *vault.Vault
	Log    *logs.Logger
	LogDir string
	Now    func() time.Time
}

// Inputs. Fields without omitempty are required by the inferred schema.
type PathIn struct {
	Path string `json:"path" jsonschema:"note path relative to the vault root, for example Library/Inbox/idea.md"`
}
type ListIn struct {
	Folder    string `json:"folder,omitempty" jsonschema:"folder relative to the vault root; empty for the root"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"list every note below the folder instead of one level"`
}
type SearchIn struct {
	Query  string `json:"query" jsonschema:"text to find, case-insensitive"`
	Folder string `json:"folder,omitempty" jsonschema:"limit the search to this folder"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum hits, default 20, at most 100"`
}
type SearchTagIn struct {
	Tag string `json:"tag" jsonschema:"tag such as topic/dev, with or without a leading #"`
}
type RecentIn struct {
	Days int `json:"days,omitempty" jsonschema:"window in days, default 1, at most 365"`
}
type CreateIn struct {
	Path    string `json:"path" jsonschema:"path of the new note; fails if it exists"`
	Content string `json:"content" jsonschema:"full Markdown content, including frontmatter if the vault uses it"`
}
type AppendIn struct {
	Path    string `json:"path" jsonschema:"existing note"`
	Text    string `json:"text" jsonschema:"Markdown to add on new lines"`
	Section string `json:"section,omitempty" jsonschema:"heading text; when set, the text goes at the end of that section"`
}
type ReplaceSectionIn struct {
	Path    string `json:"path" jsonschema:"existing note"`
	Heading string `json:"heading" jsonschema:"exact heading text of the section to replace"`
	Content string `json:"content" jsonschema:"new body of the section; replaces its subsections too"`
	Version string `json:"version" jsonschema:"version from your last read_note of this note"`
}
type UpdateFrontmatterIn struct {
	Path    string         `json:"path" jsonschema:"existing note"`
	Fields  map[string]any `json:"fields" jsonschema:"keys to set; a null value removes the key"`
	Version string         `json:"version" jsonschema:"version from your last read_note of this note"`
}
type MoveIn struct {
	From string `json:"from" jsonschema:"current path; may be inside .trash to restore a note"`
	To   string `json:"to" jsonschema:"new path; fails if it exists"`
}

// Outputs. Only strings, numbers, booleans, maps, and non-nil slices, so
// the inferred output schemas stay simple and always validate.
type NoteOut struct {
	Path             string         `json:"path"`
	Content          string         `json:"content"`
	Frontmatter      map[string]any `json:"frontmatter,omitempty"`
	FrontmatterError string         `json:"frontmatter_error,omitempty"`
	Version          string         `json:"version"`
	Modified         string         `json:"modified"`
}
type EntryOut struct {
	Path   string `json:"path"`
	Folder bool   `json:"folder,omitempty"`
}
type ListOut struct {
	Entries   []EntryOut `json:"entries"`
	Truncated bool       `json:"truncated,omitempty"`
}
type HitOut struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}
type SearchOut struct {
	Hits []HitOut `json:"hits"`
}
type PathsOut struct {
	Paths     []string `json:"paths"`
	Truncated bool     `json:"truncated,omitempty"`
}
type RecentNoteOut struct {
	Path     string   `json:"path"`
	Modified string   `json:"modified"`
	Clients  []string `json:"clients,omitempty"`
}
type RecentOut struct {
	Notes     []RecentNoteOut `json:"notes"`
	Truncated bool            `json:"truncated,omitempty"`
}
type VersionOut struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}
type MoveOut struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	StillLinking []string `json:"still_linking"`
	// BacklinksComplete is false when the move succeeded but scanning for
	// remaining links failed, so StillLinking may be incomplete.
	BacklinksComplete bool `json:"backlinks_complete"`
}
type DeleteOut struct {
	Path      string `json:"path"`
	TrashPath string `json:"trash_path"`
}

// ptr is for the optional boolean hints in mcp.ToolAnnotations.
func ptr[T any](v T) *T { return &v }

func readOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}
}

func writes(destructive, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptr(destructive), IdempotentHint: idempotent, OpenWorldHint: ptr(false)}
}

// Register adds the 12 tools to s.
func Register(s *mcp.Server, d Deps) {
	if d.Now == nil {
		d.Now = time.Now
	}
	mcp.AddTool(s, &mcp.Tool{Name: "read_note", Annotations: readOnly(), Description: "Read one note. Returns its content, parsed frontmatter, and a version: pass that version to replace_section or update_frontmatter."}, d.readNote)
	mcp.AddTool(s, &mcp.Tool{Name: "list", Annotations: readOnly(), Description: "List the notes and subfolders of a folder, or every note below it when recursive. At most 500 entries; truncated is true when more exist."}, d.list)
	mcp.AddTool(s, &mcp.Tool{Name: "search", Annotations: readOnly(), Description: "Find lines containing some text, case-insensitive. Returns paths, line numbers, and snippets. limit defaults to 20, at most 100."}, d.search)
	mcp.AddTool(s, &mcp.Tool{Name: "search_tag", Annotations: readOnly(), Description: "Find notes with a tag, in frontmatter tags or inline as #tag. At most 500 paths; truncated is true when more exist."}, d.searchTag)
	mcp.AddTool(s, &mcp.Tool{Name: "backlinks", Annotations: readOnly(), Description: "Find notes that link to a note, by wikilink or Markdown link. At most 500 paths; truncated is true when more exist."}, d.backlinks)
	mcp.AddTool(s, &mcp.Tool{Name: "recent", Annotations: readOnly(), Description: "List notes modified in the last N days (1 to 365), newest first, with the clients that changed them through this server. At most 500 notes; truncated is true when more exist."}, d.recent)
	mcp.AddTool(s, &mcp.Tool{Name: "create_note", Annotations: writes(false, false), Description: "Create a new note. Fails if the note exists: use append or replace_section to change existing notes."}, d.createNote)
	mcp.AddTool(s, &mcp.Tool{Name: "append", Annotations: writes(false, false), Description: "Add text at the end of a note, or at the end of one section. Safe without a version: it never overwrites."}, d.appendNote)
	mcp.AddTool(s, &mcp.Tool{Name: "replace_section", Annotations: writes(true, true), Description: "Replace the body of one section, including all of its subsections. A content that contains headings or code fences changes the structure of the note. Requires the version from read_note; if the note changed, read it again."}, d.replaceSection)
	mcp.AddTool(s, &mcp.Tool{Name: "update_frontmatter", Annotations: writes(false, true), Description: "Set or remove frontmatter keys without touching the body. Requires the version from read_note."}, d.updateFrontmatter)
	mcp.AddTool(s, &mcp.Tool{Name: "move_note", Annotations: writes(false, false), Description: "Move or rename a note, or restore one from .trash. Links in other notes are not rewritten: still_linking lists the notes that still link to the old path. A move that keeps the file name may still list notes with a [[name]] link, which Obsidian resolves by name. backlinks_complete is false when the move succeeded but the link scan failed."}, d.moveNote)
	mcp.AddTool(s, &mcp.Tool{Name: "delete_note", Annotations: writes(true, false), Description: "Move a note to .trash. Nothing is permanently deleted."}, d.deleteNote)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// capped cuts s to maxResults and reports whether anything was dropped.
func capped[T any](s []T) ([]T, bool) {
	if len(s) > maxResults {
		return s[:maxResults], true
	}
	return nonNil(s), false
}

// require rejects an empty (or blank) field early with a clear message; the
// vault would otherwise answer with a confusing path or lookup error.
func require(field, val string) error {
	if strings.TrimSpace(val) == "" {
		return &vault.Error{Code: vault.CodeInvalidInput, Msg: field + " must not be empty"}
	}
	return nil
}

func clientName(req *mcp.CallToolRequest) string {
	if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
		if c, ok := req.Extra.TokenInfo.Extra["client"].(string); ok && c != "" {
			return c
		}
	}
	return "unknown"
}

// toolErr turns an error into one an assistant may see. Vault errors carry
// a stable code and a safe message; anything else is logged here and
// replaced, so host paths and internals never leak.
func toolErr(tool string, err error) error {
	if vault.CodeOf(err) != "" {
		return err
	}
	slog.Error("tool failed", "tool", tool, "err", err)
	return errors.New("internal_error: the server could not complete the request")
}

// write runs one vault write, logs it (rejections included: they are how
// a misbehaving client shows up), and maps its error.
func (d Deps) write(req *mcp.CallToolRequest, tool, logPath string, fn func() error) error {
	err := fn()
	result := "ok"
	if err != nil {
		result = "internal_error"
		if c := vault.CodeOf(err); c != "" {
			result = string(c)
		}
	}
	if lerr := d.Log.Write(logs.Entry{Time: d.Now(), Client: clientName(req), Tool: tool, Path: logPath, Result: result}); lerr != nil {
		slog.Error("write log failed", "err", lerr)
	}
	if err != nil {
		return toolErr(tool, err)
	}
	return nil
}

func (d Deps) readNote(_ context.Context, _ *mcp.CallToolRequest, in PathIn) (*mcp.CallToolResult, NoteOut, error) {
	if err := require("path", in.Path); err != nil {
		return nil, NoteOut{}, err
	}
	n, err := d.Vault.Read(in.Path)
	if err != nil {
		return nil, NoteOut{}, toolErr("read_note", err)
	}
	return nil, NoteOut{
		Path: n.Path, Content: n.Content, Frontmatter: n.Frontmatter, FrontmatterError: n.FrontmatterError,
		Version: n.Version, Modified: n.Modified.Format(time.RFC3339),
	}, nil
}

func (d Deps) list(_ context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, ListOut, error) {
	es, err := d.Vault.List(in.Folder, in.Recursive)
	if err != nil {
		return nil, ListOut{}, toolErr("list", err)
	}
	out := ListOut{Entries: []EntryOut{}}
	es, out.Truncated = capped(es)
	for _, e := range es {
		out.Entries = append(out.Entries, EntryOut{Path: e.Path, Folder: e.Folder})
	}
	return nil, out, nil
}

func (d Deps) search(_ context.Context, _ *mcp.CallToolRequest, in SearchIn) (*mcp.CallToolResult, SearchOut, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	limit = min(limit, maxSearchLimit)
	hits, err := d.Vault.Search(in.Query, in.Folder, limit)
	if err != nil {
		return nil, SearchOut{}, toolErr("search", err)
	}
	out := SearchOut{Hits: []HitOut{}}
	for _, h := range hits {
		out.Hits = append(out.Hits, HitOut{Path: h.Path, Line: h.Line, Snippet: h.Snippet})
	}
	return nil, out, nil
}

func (d Deps) searchTag(_ context.Context, _ *mcp.CallToolRequest, in SearchTagIn) (*mcp.CallToolResult, PathsOut, error) {
	if err := require("tag", in.Tag); err != nil {
		return nil, PathsOut{}, err
	}
	ps, err := d.Vault.SearchTag(in.Tag)
	if err != nil {
		return nil, PathsOut{}, toolErr("search_tag", err)
	}
	ps, trunc := capped(ps)
	return nil, PathsOut{Paths: ps, Truncated: trunc}, nil
}

func (d Deps) backlinks(_ context.Context, _ *mcp.CallToolRequest, in PathIn) (*mcp.CallToolResult, PathsOut, error) {
	if err := require("path", in.Path); err != nil {
		return nil, PathsOut{}, err
	}
	ps, err := d.Vault.Backlinks(in.Path)
	if err != nil {
		return nil, PathsOut{}, toolErr("backlinks", err)
	}
	ps, trunc := capped(ps)
	return nil, PathsOut{Paths: ps, Truncated: trunc}, nil
}

func (d Deps) recent(_ context.Context, _ *mcp.CallToolRequest, in RecentIn) (*mcp.CallToolResult, RecentOut, error) {
	days := in.Days
	if days <= 0 {
		days = 1
	}
	days = min(days, 365)
	since := d.Now().Add(-time.Duration(days) * 24 * time.Hour)
	notes, err := d.Vault.Recent(since)
	if err != nil {
		return nil, RecentOut{}, toolErr("recent", err)
	}
	entries, err := logs.ReadSince(d.LogDir, since)
	if err != nil {
		slog.Warn("cannot read write log", "err", err) // the list is still useful without clients
	}
	clients := map[string][]string{}
	for _, e := range entries {
		if e.Result == "ok" && !slices.Contains(clients[e.Path], e.Client) {
			clients[e.Path] = append(clients[e.Path], e.Client)
		}
	}
	out := RecentOut{Notes: []RecentNoteOut{}}
	notes, out.Truncated = capped(notes)
	for _, n := range notes {
		out.Notes = append(out.Notes, RecentNoteOut{Path: n.Path, Modified: n.Modified.Format(time.RFC3339), Clients: clients[n.Path]})
	}
	return nil, out, nil
}

func (d Deps) createNote(_ context.Context, req *mcp.CallToolRequest, in CreateIn) (*mcp.CallToolResult, VersionOut, error) {
	var ver string
	err := d.write(req, "create_note", in.Path, func() (err error) {
		if err := require("path", in.Path); err != nil {
			return err
		}
		ver, err = d.Vault.Create(in.Path, in.Content)
		return err
	})
	if err != nil {
		return nil, VersionOut{}, err
	}
	return nil, VersionOut{Path: in.Path, Version: ver}, nil
}

func (d Deps) appendNote(_ context.Context, req *mcp.CallToolRequest, in AppendIn) (*mcp.CallToolResult, VersionOut, error) {
	var ver string
	err := d.write(req, "append", in.Path, func() (err error) {
		if err := require("path", in.Path); err != nil {
			return err
		}
		if in.Section == "" {
			ver, err = d.Vault.Append(in.Path, in.Text)
		} else {
			ver, err = d.Vault.AppendToSection(in.Path, in.Section, in.Text)
		}
		return err
	})
	if err != nil {
		return nil, VersionOut{}, err
	}
	return nil, VersionOut{Path: in.Path, Version: ver}, nil
}

func (d Deps) replaceSection(_ context.Context, req *mcp.CallToolRequest, in ReplaceSectionIn) (*mcp.CallToolResult, VersionOut, error) {
	var ver string
	err := d.write(req, "replace_section", in.Path, func() (err error) {
		if err := require("path", in.Path); err != nil {
			return err
		}
		if err := require("heading", in.Heading); err != nil {
			return err
		}
		ver, err = d.Vault.ReplaceSection(in.Path, in.Heading, in.Content, in.Version)
		return err
	})
	if err != nil {
		return nil, VersionOut{}, err
	}
	return nil, VersionOut{Path: in.Path, Version: ver}, nil
}

func (d Deps) updateFrontmatter(_ context.Context, req *mcp.CallToolRequest, in UpdateFrontmatterIn) (*mcp.CallToolResult, VersionOut, error) {
	var ver string
	err := d.write(req, "update_frontmatter", in.Path, func() (err error) {
		if err := require("path", in.Path); err != nil {
			return err
		}
		ver, err = d.Vault.UpdateFrontmatter(in.Path, in.Fields, in.Version)
		return err
	})
	if err != nil {
		return nil, VersionOut{}, err
	}
	return nil, VersionOut{Path: in.Path, Version: ver}, nil
}

func (d Deps) moveNote(_ context.Context, req *mcp.CallToolRequest, in MoveIn) (*mcp.CallToolResult, MoveOut, error) {
	var still []string
	complete := true
	err := d.write(req, "move_note", in.From+" -> "+in.To, func() (err error) {
		if err := require("from", in.From); err != nil {
			return err
		}
		if err := require("to", in.To); err != nil {
			return err
		}
		still, complete, err = d.Vault.Move(in.From, in.To)
		return err
	})
	if err != nil {
		return nil, MoveOut{}, err
	}
	return nil, MoveOut{From: in.From, To: in.To, StillLinking: nonNil(still), BacklinksComplete: complete}, nil
}

func (d Deps) deleteNote(_ context.Context, req *mcp.CallToolRequest, in PathIn) (*mcp.CallToolResult, DeleteOut, error) {
	var trash string
	err := d.write(req, "delete_note", in.Path, func() (err error) {
		if err := require("path", in.Path); err != nil {
			return err
		}
		trash, err = d.Vault.Delete(in.Path)
		return err
	})
	if err != nil {
		return nil, DeleteOut{}, err
	}
	return nil, DeleteOut{Path: in.Path, TrashPath: trash}, nil
}
