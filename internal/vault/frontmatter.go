package vault

import (
	"fmt"
	"math"
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

// stringifyDates makes decoded frontmatter JSON-safe. yaml.v3 yields
// time.Time for timestamp-like scalars, map[any]any for maps with non-string
// keys, and NaN/Inf floats for ".nan"/".inf"; encoding/json renders the first
// two wrongly for clients and rejects the third.
//
// Rendering rule: a time.Time at midnight UTC becomes YYYY-MM-DD, any other
// becomes RFC3339 (nanoseconds only when present); non-string keys become
// fmt.Sprint(key); NaN and infinities become the strings "NaN", "+Inf" and
// "-Inf". This is lossy by design: the original spelling is not kept (a
// datetime written "2026-10-01 10:30:00" comes back as RFC3339, an explicit
// midnight-UTC datetime comes back date-only). Decoding into yaml.Node would
// keep the text but bypass the decoder's alias-expansion limits on untrusted
// input.
func stringifyDates(v any) any {
	switch x := v.(type) {
	case time.Time:
		if x.Location() == time.UTC && x.Equal(x.Truncate(24*time.Hour)) {
			return x.Format(time.DateOnly)
		}
		return x.Format(time.RFC3339Nano)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x)
		}
	case map[string]any:
		for k, val := range x {
			x[k] = stringifyDates(val)
		}
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(k)] = stringifyDates(val)
		}
		return m
	case []any:
		for i, val := range x {
			x[i] = stringifyDates(val)
		}
	}
	return v
}
