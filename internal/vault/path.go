package vault

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// neverAccessible are top-level folders no tool may read or write.
var neverAccessible = []string{".git", ".obsidian", ".cortex-mcp"}

// trashDir receives deleted notes. It is readable and may be a move
// source (to restore a note), but no tool writes into it directly.
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
	p := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rel)), "./")
	if p == "" || p == "." {
		if wantMD {
			return "", errf(CodeInvalidPath, "a note path is required")
		}
		return ".", nil
	}
	if strings.HasPrefix(p, "/") || filepath.IsAbs(rel) || strings.ContainsRune(p, 0) {
		return "", errf(CodePathOutside, "paths must be relative to the vault root")
	}
	if !filepath.IsLocal(filepath.FromSlash(p)) {
		return "", errf(CodePathOutside, "path %q leaves the vault", rel)
	}
	p = path.Clean(p)
	if wantMD && !strings.EqualFold(path.Ext(p), ".md") {
		return "", errf(CodeNotMarkdown, "only .md notes are supported")
	}
	top := strings.SplitN(p, "/", 2)[0]
	for _, n := range neverAccessible {
		if top == n {
			return "", errf(CodePathProtected, "%s is protected", n)
		}
	}
	if top == trashDir && a == accessWrite {
		return "", errf(CodePathProtected, ".trash is receive-only: use delete_note to trash a note and move_note to restore it")
	}
	for _, d := range v.deny {
		if p == d || strings.HasPrefix(p, d+"/") {
			return "", errf(CodePathProtected, "%s is protected by the server configuration", d)
		}
	}
	return p, nil
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
		// TestReadRefusesSymlinksLeavingTheVault guards the string.
		return errf(CodePathOutside, "%s resolves outside the vault", rel)
	default:
		return err
	}
}
