// Package vault is the only code in cortex-mcp that touches the filesystem.
// It knows nothing about MCP, HTTP, or auth.
package vault

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable error code shown to assistants.
type Code string

// Codes, as assistants see them. They are part of the tool contract: never
// rename one.
const (
	// CodeInvalidPath: the path is malformed (characters, length, empty), is
	// a folder where a note was expected, or passes through a symlink.
	CodeInvalidPath Code = "invalid_path"
	// CodePathOutside: the path is absolute or leaves the vault.
	CodePathOutside Code = "path_outside_vault"
	// CodePathProtected: the path is never accessible (.git, .obsidian,
	// .cortex-mcp), denied by the config, the receive-only trash, or the
	// read-only instructions file.
	CodePathProtected Code = "path_protected"
	// CodeNotMarkdown: only .md notes are supported.
	CodeNotMarkdown Code = "not_markdown"
	// CodeNotFound: the note or folder does not exist.
	CodeNotFound Code = "note_not_found"
	// CodeExists: the target of a create or move already exists.
	CodeExists Code = "note_exists"
	// CodeChanged: a guarded edit presented a stale version.
	CodeChanged Code = "note_changed"
	// CodeVersionRequired: a guarded edit presented no version.
	CodeVersionRequired Code = "version_required"
	// CodeSectionNotFound: no heading matches the requested section.
	CodeSectionNotFound Code = "section_not_found"
	// CodeSectionAmbiguous: several headings match the requested section.
	CodeSectionAmbiguous Code = "section_ambiguous"
	// CodeTooLarge: the input of one write is over the write limit.
	CodeTooLarge Code = "write_too_large"
	// CodeBadFrontmatter: the frontmatter cannot be parsed, is over its size
	// cap, or an update would leave it unreadable.
	CodeBadFrontmatter Code = "frontmatter_invalid"
	// CodeInvalidInput: a required argument is empty or inconsistent.
	CodeInvalidInput Code = "invalid_input"
	// CodeDiskLow: the vault's disk is below the free-space floor; writes
	// are paused.
	CodeDiskLow Code = "disk_low"
	// CodeNoteTooLarge: the note is (or a modification would make it) larger
	// than the largest note the vault reads.
	CodeNoteTooLarge Code = "note_too_large"
)

// Error is a vault error with a stable code and an actionable message.
// Messages contain vault-relative paths only, never host paths.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Msg }

func errf(c Code, format string, a ...any) error {
	return &Error{Code: c, Msg: fmt.Sprintf(format, a...)}
}

// CodeOf returns the Code of err, or "" if err is not a vault error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
