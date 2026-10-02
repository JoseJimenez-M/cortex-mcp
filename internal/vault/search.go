package vault

import (
	"errors"
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Entry is one item of a folder listing.
type Entry struct {
	Path   string
	Folder bool
}

// Hit is one matching line of a search.
type Hit struct {
	Path    string
	Line    int // 1-based
	Snippet string
}

// RecentNote is a note modified inside a time window.
type RecentNote struct {
	Path     string
	Modified time.Time
}

var (
	inlineTag = regexp.MustCompile(`(?:^|\s)#([\p{L}\p{N}_/\-]+)`)
	wikiLink  = regexp.MustCompile(`\[\[([^\[\]|#^]+)`)
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+?\.md)(?:#[^)]*)?\)`)
	errStop   = errors.New("stop walking")
)

// hidden reports paths that walks and listings skip. It reuses
// protectedErr, the single definition clean enforces, so a walk can never
// expose what clean refuses: neverAccessible names at any depth, the deny
// list, and the top-level trash.
func (v *Vault) hidden(p string) bool {
	return v.protectedErr(p, accessRead) != nil || isTrash(p)
}

// isTrash reports whether p is inside the top-level trash folder.
func isTrash(p string) bool {
	return foldEq(strings.SplitN(p, "/", 2)[0], trashDir)
}

// visible applies hidden, except when walking a folder other than the vault
// root: clean already accepted that folder, so the trash can only be shown
// because the folder is the trash or inside it (an ordinary folder cannot
// contain the top-level trash). Never-accessible names and deny entries stay
// hidden there too.
func (v *Vault) visible(p, folder string) bool {
	if folder == "." {
		return !v.hidden(p)
	}
	return v.protectedErr(p, accessRead) == nil
}

func isNote(name string) bool {
	return foldEq(path.Ext(name), ".md") && !strings.HasPrefix(name, ".cortex-tmp-")
}

// noteInfo returns the metadata of a listed or walked entry when it is a
// regular note file. The vault never follows symlinks (see noSymlinks), so a
// symlinked note is skipped here: d.Info is an Lstat and reports the link.
func noteInfo(d fs.DirEntry) (fs.FileInfo, bool) {
	if !d.Type().IsRegular() || !isNote(d.Name()) {
		return nil, false
	}
	info, err := d.Info()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	return info, true
}

// walk calls fn for every visible note under folder, in lexical order.
// fs.WalkDir does not follow symlinked folders, so a link out of the vault
// is never entered.
func (v *Vault) walk(folder string, fn func(p string, info fs.FileInfo) error) error {
	return fs.WalkDir(v.root.FS(), folder, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable entry must not abort the whole scan.
			if p != folder && errors.Is(err, fs.ErrPermission) {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return fsErr(err, p)
		}
		if p != folder && !v.visible(p, folder) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never followed, file or folder
		}
		info, ok := noteInfo(d)
		if !ok {
			return nil
		}
		return fn(p, info)
	})
}

// readForScan reads a note during a walk. Notes that cannot be read for a
// vault reason (a symlink) or a permission reason (mode 000) are skipped, not fatal.
// Frontmatter is parsed only when withFM is set: only the tag scan needs it.
func (v *Vault) readForScan(p string, withFM bool) (*Note, bool, error) {
	read := v.readContent
	if withFM {
		read = v.read
	}
	n, err := read(p)
	if err != nil {
		if CodeOf(err) != "" || errors.Is(err, fs.ErrPermission) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return n, true, nil
}

// checkFolder verifies that cleaned path f is an existing real folder.
func (v *Vault) checkFolder(f string) error {
	if err := v.noSymlinks(f); err != nil {
		return err
	}
	info, err := v.root.Stat(filepath.FromSlash(f))
	if err != nil {
		return fsErr(err, f)
	}
	if !info.IsDir() {
		return errf(CodeInvalidPath, "%s is not a folder", f)
	}
	return nil
}

// List returns a folder's notes and subfolders, or every note below it
// when recursive.
func (v *Vault) List(folder string, recursive bool) ([]Entry, error) {
	f, err := v.clean(folder, accessRead, false)
	if err != nil {
		return nil, err
	}
	if err := v.checkFolder(f); err != nil {
		return nil, err
	}
	var out []Entry
	if recursive {
		err := v.walk(f, func(p string, _ fs.FileInfo) error {
			out = append(out, Entry{Path: p})
			return nil
		})
		return out, err
	}
	ents, err := fs.ReadDir(v.root.FS(), f)
	if err != nil {
		return nil, fsErr(err, f)
	}
	for _, e := range ents {
		p := path.Join(f, e.Name())
		if !v.visible(p, f) {
			continue
		}
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if e.IsDir() {
			out = append(out, Entry{Path: p, Folder: true})
		} else if _, ok := noteInfo(e); ok {
			out = append(out, Entry{Path: p})
		}
	}
	return out, nil
}

// Search limits: the number of hits when none is asked for, and the most a
// caller may ask for.
const (
	DefaultSearchLimit = 20
	MaxSearchLimit     = 100
)

// Search finds lines containing query (case-insensitive substring, using
// strings.ToLower, which is simple lowercasing: good for accents and
// Cyrillic, not full Unicode case folding). Lines are split on "\n" and
// the snippet is trimmed, so CRLF notes yield no trailing "\r". Hits come in
// lexical path order. limit defaults to DefaultSearchLimit and is capped at
// MaxSearchLimit.
func (v *Vault) Search(query, folder string, limit int) ([]Hit, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, errf(CodeInvalidInput, "query is empty")
	}
	if limit <= 0 {
		limit = DefaultSearchLimit
	}
	limit = min(limit, MaxSearchLimit)
	f, err := v.clean(folder, accessRead, false)
	if err != nil {
		return nil, err
	}
	if err := v.checkFolder(f); err != nil {
		return nil, err
	}
	var hits []Hit
	err = v.walk(f, func(p string, _ fs.FileInfo) error {
		n, ok, err := v.readForScan(p, false)
		if !ok {
			return err
		}
		for i, line := range strings.Split(n.Content, "\n") {
			lower := strings.ToLower(line)
			if idx := strings.Index(lower, q); idx >= 0 {
				// ToLower maps rune to rune, so rune offsets agree.
				at := utf8.RuneCountInString(lower[:idx])
				hits = append(hits, Hit{Path: p, Line: i + 1, Snippet: snippet(line, at)})
				if len(hits) >= limit {
					return errStop
				}
			}
		}
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return hits, err
}

// snippet returns at most snippetRunes runes of line, starting snippetBefore
// runes before the match (at rune offset matchRune) so the match stays
// visible on very long lines. It never converts the whole line to runes.
func snippet(line string, matchRune int) string {
	const snippetRunes, snippetBefore = 200, 80
	start := max(0, matchRune-snippetBefore)
	b := 0
	for i := 0; i < start && b < len(line); i++ {
		_, w := utf8.DecodeRuneInString(line[b:])
		b += w
	}
	rest := line[b:]
	end := 0
	for n := 0; n < snippetRunes && end < len(rest); n++ {
		_, w := utf8.DecodeRuneInString(rest[end:])
		end += w
	}
	out := strings.TrimSpace(rest[:end])
	if start > 0 {
		out = "..." + out
	}
	if strings.TrimSpace(rest[end:]) != "" {
		out += "..."
	}
	return out
}

// SearchTag returns notes tagged with tag, in frontmatter `tags` or inline
// as #tag. A leading "#" in the request is ignored.
func (v *Vault) SearchTag(tag string) ([]string, error) {
	t := strings.TrimPrefix(strings.TrimSpace(tag), "#")
	if t == "" {
		return nil, errf(CodeInvalidInput, "tag is empty")
	}
	var out []string
	err := v.walk(".", func(p string, _ fs.FileInfo) error {
		n, ok, err := v.readForScan(p, true)
		if !ok {
			return err
		}
		if hasTag(n, t) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func hasTag(n *Note, t string) bool {
	switch tags := n.Frontmatter["tags"].(type) {
	case []any:
		for _, x := range tags {
			if s, ok := x.(string); ok && strings.TrimPrefix(s, "#") == t {
				return true
			}
		}
	case string:
		for _, s := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ' ' }) {
			if strings.TrimPrefix(s, "#") == t {
				return true
			}
		}
	}
	_, body, _, _ := splitFrontmatter(n.Content)
	for _, m := range inlineTag.FindAllStringSubmatch(body, -1) {
		if m[1] == t {
			return true
		}
	}
	return false
}

// Recent returns notes modified at or after since, newest first.
func (v *Vault) Recent(since time.Time) ([]RecentNote, error) {
	var out []RecentNote
	err := v.walk(".", func(p string, info fs.FileInfo) error {
		if !info.ModTime().Before(since) {
			out = append(out, RecentNote{Path: p, Modified: info.ModTime().UTC()})
		}
		return nil
	})
	// Stable, so notes with equal mtimes keep the walk's lexical order.
	slices.SortStableFunc(out, newestFirst)
	return out, err
}

// newestFirst orders RecentNote by descending modification time.
func newestFirst(a, b RecentNote) int { return b.Modified.Compare(a.Modified) }

// Backlinks returns the notes that link to rel.
func (v *Vault) Backlinks(rel string) ([]string, error) {
	target, err := v.clean(rel, accessRead, true)
	if err != nil {
		return nil, err
	}
	if err := v.noSymlinks(target); err != nil {
		return nil, err
	}
	noExt := strings.TrimSuffix(target, path.Ext(target))
	base := path.Base(noExt)
	var out []string
	err = v.walk(".", func(p string, _ fs.FileInfo) error {
		if p == target {
			return nil
		}
		n, ok, err := v.readForScan(p, false)
		if !ok {
			return err
		}
		if linksTo(n.Content, p, noExt, base) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func linksTo(content, from, noExt, base string) bool {
	for _, m := range wikiLink.FindAllStringSubmatch(content, -1) {
		l := strings.TrimSuffix(strings.TrimSpace(m[1]), ".md")
		if l == noExt || l == base {
			return true
		}
	}
	for _, m := range mdLink.FindAllStringSubmatch(content, -1) {
		l, err := url.PathUnescape(m[1])
		if err != nil {
			l = m[1]
		}
		if strings.Contains(l, "://") {
			continue
		}
		resolved := path.Join(path.Dir(from), l)
		if strings.HasPrefix(l, "/") {
			resolved = strings.TrimPrefix(path.Clean(l), "/")
		}
		if strings.TrimSuffix(resolved, path.Ext(resolved)) == noExt {
			return true
		}
	}
	return false
}
