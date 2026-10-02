package vault

import (
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// splitFrontmatter splits content into the YAML between the opening and
// closing "---" lines and the body after them. ok is false when the note
// has no frontmatter, and body is then the whole content. Handles a UTF-8
// BOM and CRLF line endings.
func splitFrontmatter(content string) (yamlText, body string, ok bool, err error) {
	s := strings.TrimPrefix(content, "\uFEFF")
	first, rest, found := strings.Cut(s, "\n")
	if strings.TrimRight(first, "\r") != "---" {
		return "", content, false, nil
	}
	if !found {
		return "", "", false, errf(CodeBadFrontmatter, "frontmatter is not closed with ---")
	}
	var b strings.Builder
	for {
		line, after, more := strings.Cut(rest, "\n")
		if strings.TrimRight(line, "\r") == "---" {
			return b.String(), after, true, nil
		}
		if !more {
			return "", "", false, errf(CodeBadFrontmatter, "frontmatter is not closed with ---")
		}
		b.WriteString(line)
		b.WriteString("\n")
		rest = after
	}
}

// parseFrontmatter returns the frontmatter as a map, or nil when the note
// has none.
func parseFrontmatter(content string) (map[string]any, error) {
	y, _, ok, err := splitFrontmatter(content)
	if err != nil || !ok {
		return nil, err
	}
	m := map[string]any{}
	if err := yaml.Unmarshal([]byte(y), &m); err != nil {
		return nil, errf(CodeBadFrontmatter, "frontmatter is not valid YAML: %v", err)
	}
	for k, val := range m {
		m[k] = stringifyDates(val)
	}
	return m, nil
}

// stringifyDates turns the time.Time values yaml.v3 produces for
// timestamp-like scalars back into strings, so clients see "2026-10-01" as
// written. Decoding into yaml.Node instead would avoid the round trip but
// would bypass the decoder's alias-expansion limits on untrusted input.
// A midnight UTC timestamp is rendered date-only (the vault's convention).
func stringifyDates(v any) any {
	switch x := v.(type) {
	case time.Time:
		if x.Location() == time.UTC && x.Equal(x.Truncate(24*time.Hour)) {
			return x.Format(time.DateOnly)
		}
		return x.Format(time.RFC3339Nano)
	case map[string]any:
		for k, val := range x {
			x[k] = stringifyDates(val)
		}
	case []any:
		for i, val := range x {
			x[i] = stringifyDates(val)
		}
	}
	return v
}
