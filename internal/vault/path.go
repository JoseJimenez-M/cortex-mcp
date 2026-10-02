package vault

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// neverAccessible are folder names no tool may read or write at any depth
// (vaults may contain nested git repos), matched case-insensitively because
// default macOS and Windows filesystems are case-insensitive.
var neverAccessible = []string{".git", ".obsidian", ".cortex-mcp"}

// trashDir receives deleted notes. It is readable and may be a move
// source (to restore a note), but no tool writes into it directly. Only the
// top-level folder is the trash (where Obsidian puts it), matched
// case-insensitively.
const trashDir = ".trash"

type access int

const (
	accessRead     access = iota // read a note or list a folder
	accessWrite                  // create or modify a note
	accessMoveFrom               // source of move_note, may be inside .trash
)

// clean validates an assistant-supplied path and returns it in canonical
// slash form. "." is the vault root and is only valid when wantMD is false.
// This is the first line of defence and gives clear error codes; os.Root
// is the second and also catches symlinks.
func (v *Vault) clean(rel string, a access, wantMD bool) (string, error) {
	if err := checkChars(rel); err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) {
		return "", errf(CodePathOutside, "paths must be relative to the vault root")
	}
	// path.Clean folds repeated "./" and "//" ("" and "./" become "."), so
	// no one-shot prefix trimming is needed.
	p := path.Clean(rel)
	if p == "." {
		if wantMD {
			return "", errf(CodeInvalidPath, "a note path is required")
		}
		return ".", nil
	}
	if !filepath.IsLocal(filepath.FromSlash(p)) {
		return "", errf(CodePathOutside, "path %q leaves the vault", rel)
	}
	if wantMD && !strings.EqualFold(path.Ext(p), ".md") {
		return "", errf(CodeNotMarkdown, "only .md notes are supported")
	}
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		for _, n := range neverAccessible {
			if strings.EqualFold(seg, n) {
				return "", errf(CodePathProtected, "%s is protected", n)
			}
		}
	}
	if a == accessWrite && strings.EqualFold(segs[0], trashDir) {
		return "", errf(CodePathProtected, ".trash is receive-only: use delete_note to trash a note and move_note to restore it")
	}
	lp := strings.ToLower(p)
	for _, d := range v.deny {
		ld := strings.ToLower(d)
		if lp == ld || strings.HasPrefix(lp, ld+"/") {
			return "", errf(CodePathProtected, "%s is protected by the server configuration", d)
		}
	}
	return p, nil
}

// checkChars rejects input that is ambiguous across platforms or unsafe to
// echo: control characters (including NUL), backslash (a separator on
// Windows), and leading or trailing whitespace. Whitespace is rejected, not
// trimmed, so the path that is checked is the path that is used.
func checkChars(rel string) error {
	for _, r := range rel {
		if unicode.IsControl(r) || r == '\\' {
			return errf(CodeInvalidPath, "paths may not contain control characters or backslashes")
		}
	}
	first, _ := utf8.DecodeRuneInString(rel)
	last, _ := utf8.DecodeLastRuneInString(rel)
	if rel != "" && (unicode.IsSpace(first) || unicode.IsSpace(last)) {
		return errf(CodeInvalidPath, "paths may not start or end with whitespace")
	}
	return nil
}

// fsErr maps filesystem errors to vault errors without leaking host paths.
// Errors it does not recognise are returned as is: the tools layer logs
// them and shows the assistant a generic message.
func fsErr(err error, rel string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return errf(CodeNotFound, "%s does not exist", rel)
	case errors.Is(err, fs.ErrExist):
		return errf(CodeExists, "%s already exists", rel)
	case strings.Contains(err.Error(), "path escapes from parent"):
		// os.Root refused a symlink that resolves outside the vault. The
		// standard library does not export this error, so match its text;
		// TestFsErrMapsRootSymlinkEscape guards the string.
		return errf(CodePathOutside, "%s resolves outside the vault", rel)
	default:
		return err
	}
}
