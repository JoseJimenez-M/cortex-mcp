// Package vault is the only code in cortex-mcp that touches the filesystem.
// It knows nothing about MCP, HTTP, or auth.
package vault

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable error code shown to assistants.
type Code string

const (
	CodeInvalidPath      Code = "invalid_path"
	CodePathOutside      Code = "path_outside_vault"
	CodePathProtected    Code = "path_protected"
	CodeNotMarkdown      Code = "not_markdown"
	CodeNotFound         Code = "note_not_found"
	CodeExists           Code = "note_exists"
	CodeChanged          Code = "note_changed"
	CodeVersionRequired  Code = "version_required"
	CodeSectionNotFound  Code = "section_not_found"
	CodeSectionAmbiguous Code = "section_ambiguous"
	CodeTooLarge         Code = "write_too_large"
	CodeBadFrontmatter   Code = "frontmatter_invalid"
	CodeInvalidInput     Code = "invalid_input"
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
