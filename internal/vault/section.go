package vault

import (
	"fmt"
	"slices"
	"strings"
)

type heading struct {
	line  int // index into the note's lines
	level int // 1 for "#", up to 6
	text  string
}

// bodyStart returns the index of the first line after a closed frontmatter
// block, or 0. Only line 0 can open frontmatter, so a "---" further down
// (a thematic break, or a setext underline) is never mistaken for it.
func bodyStart(lines []string) int {
	if len(lines) == 0 || strings.TrimRight(strings.TrimPrefix(lines[0], "\uFEFF"), "\r") != "---" {
		return 0
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == "---" {
			return i + 1
		}
	}
	return 0
}

// fenceRun reports the fence character and run length when t (already
// stripped of up to 3 spaces of indent) starts a code fence. A backtick
// fence cannot have a backtick in its info string (CommonMark), which
// keeps inline code such as "```x```" from opening a block.
func fenceRun(t string) (ch byte, n int) {
	if t == "" || (t[0] != '`' && t[0] != '~') {
		return 0, 0
	}
	ch = t[0]
	for n < len(t) && t[n] == ch {
		n++
	}
	if n < 3 || (ch == '`' && strings.Contains(t[n:], "`")) {
		return 0, 0
	}
	return ch, n
}

// parseHeadings finds ATX headings ("## Title"), skipping frontmatter,
// fenced code blocks, and indented code, so "# comment" in code is not a
// heading and "#tag" is not either. A fence closes only on the same
// character with a run at least as long as the opener.
//
// Not supported, by design: setext headings (a text line underlined with
// "===" or "---"), and headings inside HTML comments or blockquotes
// ("> # x"). They are treated as plain text, so a section cannot be
// addressed through them, but they never produce a wrong match either.
func parseHeadings(lines []string) []heading {
	var hs []heading
	var fenceCh byte
	fenceLen := 0
	for i := bodyStart(lines); i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		t := strings.TrimLeft(l, " ")
		if len(l)-len(t) > 3 {
			continue
		}
		if fenceCh != 0 {
			if ch, n := fenceRun(t); ch == fenceCh && n >= fenceLen && strings.TrimSpace(t[n:]) == "" {
				fenceCh, fenceLen = 0, 0
			}
			continue
		}
		if ch, n := fenceRun(t); ch != 0 {
			fenceCh, fenceLen = ch, n
			continue
		}
		level := 0
		for level < len(t) && t[level] == '#' {
			level++
		}
		if level == 0 || level > 6 || (level < len(t) && t[level] != ' ' && t[level] != '\t') {
			continue
		}
		text := strings.TrimSpace(t[level:])
		// A closing "##" run counts only when separated by a space, so
		// "Learn C#" keeps its "#".
		if trimmed := strings.TrimRight(text, "#"); trimmed != text && (trimmed == "" || strings.HasSuffix(trimmed, " ")) {
			text = strings.TrimSpace(trimmed)
		}
		hs = append(hs, heading{line: i, level: level, text: text})
	}
	return hs
}

// findSection returns the heading's line and the end of its section: the
// next heading of the same or higher level, or len(lines). The title must
// match exactly one heading, whatever its level.
func findSection(lines []string, title string) (start, end int, err error) {
	want := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(title), "#"))
	if want == "" {
		return 0, 0, errf(CodeInvalidInput, "section name is empty")
	}
	hs := parseHeadings(lines)
	var matches []int
	for i, h := range hs {
		if h.text == want {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		names := make([]string, 0, len(hs))
		for _, h := range hs[:min(len(hs), 20)] {
			names = append(names, fmt.Sprintf("%q", h.text))
		}
		return 0, 0, errf(CodeSectionNotFound, "no heading %q; headings are: %s", want, strings.Join(names, ", "))
	case 1:
	default:
		return 0, 0, errf(CodeSectionAmbiguous, "%d headings are named %q: edit with append or ask the owner to rename one", len(matches), want)
	}
	h := hs[matches[0]]
	end = len(lines)
	for _, n := range hs[matches[0]+1:] {
		if n.level <= h.level {
			end = n.line
			break
		}
	}
	return h.line, end, nil
}

// contentEnd moves end back over blank lines, so new text lands right after
// the section's last content line and the blank separator before the next
// heading stays where it was.
func contentEnd(lines []string, start, end int) int {
	for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	return end
}

// splitInsert turns text into lines that match the note's line endings:
// lines keep a trailing "\r" in a CRLF note (judged by the heading line),
// and any "\r" in the text is normalised first so endings never mix.
func splitInsert(text string, crlf bool) []string {
	out := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if crlf {
		for i := range out {
			out[i] += "\r"
		}
	}
	return out
}

func appendToSection(content, section, text string) (string, error) {
	lines := strings.Split(content, "\n")
	start, end, err := findSection(lines, section)
	if err != nil {
		return "", err
	}
	pos := contentEnd(lines, start, end)
	ins := splitInsert(strings.TrimRight(text, "\r\n"), strings.HasSuffix(lines[start], "\r"))
	return strings.Join(slices.Concat(lines[:pos], ins, lines[pos:]), "\n"), nil
}

func replaceSection(content, section, body string) (string, error) {
	lines := strings.Split(content, "\n")
	start, end, err := findSection(lines, section)
	if err != nil {
		return "", err
	}
	pos := contentEnd(lines, start, end)
	crlf := strings.HasSuffix(lines[start], "\r")
	var lead, ins []string
	if start+1 < pos && strings.TrimSpace(lines[start+1]) == "" {
		lead = splitInsert("", crlf) // keep the note's "blank line after heading" style
	}
	if b := strings.Trim(body, "\r\n"); b != "" {
		ins = splitInsert(b, crlf)
	}
	return strings.Join(slices.Concat(lines[:start+1], lead, ins, lines[pos:]), "\n"), nil
}

// AppendToSection adds text at the end of a section (after its
// subsections). No version needed: appending cannot clobber.
func (v *Vault) AppendToSection(rel, section, text string) (string, error) {
	if strings.TrimSpace(text) == "" {
		return "", errf(CodeInvalidInput, "nothing to append")
	}
	if err := v.checkSize(len(text)); err != nil {
		return "", err
	}
	return v.modify(rel, "", false, func(c string) (string, error) { return appendToSection(c, section, text) })
}

// ReplaceSection replaces a section's body, subsections included, and
// requires the version from the caller's last read.
func (v *Vault) ReplaceSection(rel, section, body, ver string) (string, error) {
	if err := v.checkSize(len(body)); err != nil {
		return "", err
	}
	return v.modify(rel, ver, true, func(c string) (string, error) { return replaceSection(c, section, body) })
}
