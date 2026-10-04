package vault

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// neverAccessible are folder names no tool may read or write at any depth
// (vaults may contain nested git repos), matched case-insensitively because
// default macOS and Windows filesystems are case-insensitive. .stversions
// and .stfolder are Syncthing's: a vault synced with file versioning holds
// old copies of notes in .stversions, which searches would mix with the
// current ones and which Syncthing never syncs back, so an edit there would
// be lost without notice.
var neverAccessible = []string{".git", ".obsidian", ".cortex-mcp", ".stversions", ".stfolder"}

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
	// Length first: everything after it (and every error message) is linear
	// in the input, and no real note path comes near these limits.
	if err := checkLength(rel); err != nil {
		return "", err
	}
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
	if wantMD && !foldEq(path.Ext(p), ".md") {
		return "", errf(CodeNotMarkdown, "only .md notes are supported")
	}
	if err := v.protectedErr(p, a); err != nil {
		return "", err
	}
	return p, nil
}

// noSymlinks refuses a cleaned path when any existing segment from the root
// down is a symbolic link. The vault never follows symlinks: protection is
// checked on the lexical path, so a link inside the vault could otherwise
// alias a denied or protected path (Lib/x.md -> ../Private/p.md). Missing
// segments are fine (a note about to be created). os.Root stays the second
// line of defence against links that leave the vault. Call it right after
// clean in every method that touches an existing path.
func (v *Vault) noSymlinks(p string) error {
	if p == "." {
		return nil
	}
	segs := strings.Split(p, "/")
	for i := range segs {
		prefix := strings.Join(segs[:i+1], "/")
		info, err := v.root.Lstat(filepath.FromSlash(prefix))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return fsErr(err, prefix)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return errf(CodeInvalidPath, "%s is or passes through a symbolic link; symlinks are not followed", p)
		}
	}
	return nil
}

// protectedErr is the single definition of which cleaned, slash-separated
// paths are off limits: neverAccessible names at any depth, the top-level
// trash for writes, the operator's deny list (also below the trash), and the
// read-only files for writes and moves. Everything folds case with
// fold (unicode simple folding), segment by segment, so all rules agree on what "the same
// name" means. Any later folder walk (listing, search) MUST call this same
// helper on each entry so it cannot expose what clean refuses.
func (v *Vault) protectedErr(p string, a access) error {
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		for _, n := range neverAccessible {
			if foldEq(seg, n) {
				return errf(CodePathProtected, "%s is protected", n)
			}
		}
	}
	if a == accessWrite && foldEq(segs[0], trashDir) {
		return errf(CodePathProtected, ".trash is receive-only: use delete_note to trash a note and move_note to restore it")
	}
	// Delete keeps the folder path inside the trash, so a denied note that
	// was trashed by hand (or before the entry was added) lives at
	// .trash/<denied path>: match the deny list there too. Obsidian's own
	// trash flattens paths, which no rule can match; see the README.
	inTrash := len(segs) > 1 && foldEq(segs[0], trashDir)
	for _, d := range v.deny {
		ds := strings.Split(d, "/")
		if hasFoldPrefix(segs, ds) || (inTrash && hasFoldPrefix(segs[1:], ds)) {
			return errf(CodePathProtected, "%s is protected by the server configuration", d)
		}
	}
	if a != accessRead {
		for _, ro := range v.readOnly {
			rs := strings.Split(ro, "/")
			if len(rs) == len(segs) && hasFoldPrefix(segs, rs) {
				return errf(CodePathProtected, "%s is the server instructions file: tools may read it but not change, move, or delete it", ro)
			}
		}
	}
	return nil
}

// hasFoldPrefix reports whether prefix is a segment-wise fold-equal prefix of segs.
func hasFoldPrefix(segs, prefix []string) bool {
	if len(prefix) > len(segs) {
		return false
	}
	for i, ps := range prefix {
		if !foldEq(segs[i], ps) {
			return false
		}
	}
	return true
}

// Path length caps, in bytes. 255 is NAME_MAX on Linux and macOS and 1024
// is below every PATH_MAX in use, so a longer path could never be created
// anyway; refusing early keeps a hostile megabyte-long path from costing
// work in the protection checks or being echoed back in messages.
const (
	maxPathBytes    = 1024
	maxSegmentBytes = 255
)

// checkLength enforces maxPathBytes and maxSegmentBytes. Messages do not
// echo the path: it may be huge.
func checkLength(rel string) error {
	if len(rel) > maxPathBytes {
		return errf(CodeInvalidPath, "paths may be at most %d bytes", maxPathBytes)
	}
	for _, seg := range strings.Split(rel, "/") {
		if len(seg) > maxSegmentBytes {
			return errf(CodeInvalidPath, "path segments may be at most %d bytes", maxSegmentBytes)
		}
	}
	return nil
}

// checkChars rejects input that is ambiguous across platforms or unsafe to
// echo: invalid UTF-8, control and Unicode format characters (NUL, bidi
// overrides, zero-width and BOM), backslash (a separator on Windows), and
// leading or trailing whitespace on the whole string and on every segment.
// Whitespace is rejected, not trimmed, so the path that is checked is the
// path that is used. config.checkChars (internal/config/config.go) mirrors
// this rule for config values; config_vault_test.go keeps the two in sync.
func checkChars(rel string) error {
	if !utf8.ValidString(rel) {
		return errf(CodeInvalidPath, "paths must be valid UTF-8")
	}
	for _, r := range rel {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\\' {
			return errf(CodeInvalidPath, "paths may not contain control or format characters or backslashes")
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" {
			continue
		}
		first, _ := utf8.DecodeRuneInString(seg)
		last, _ := utf8.DecodeLastRuneInString(seg)
		if unicode.IsSpace(first) || unicode.IsSpace(last) {
			return errf(CodeInvalidPath, "path segments may not start or end with whitespace")
		}
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
	case errors.Is(err, syscall.ENOTDIR):
		return errf(CodeInvalidPath, "%s: a parent of this path is a file, not a folder", rel)
	case strings.Contains(err.Error(), "path escapes from parent"):
		// os.Root refused a symlink that resolves outside the vault. The
		// standard library does not export this error, so match its text;
		// TestFsErrMapsRootSymlinkEscape guards the string.
		return errf(CodePathOutside, "%s resolves outside the vault", rel)
	default:
		return err
	}
}
