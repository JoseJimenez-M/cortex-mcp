package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// maxFrontmatterBytes caps the YAML block that is decoded. Decoding cost
// grows with the block (a 1 MiB flow sequence takes a fifth of a second and
// many MB of allocations), and real frontmatter is a few hundred bytes. A
// larger block is reported as invalid; the note itself stays readable.
const maxFrontmatterBytes = 64 << 10

func errFrontmatterTooLarge() error {
	return errf(CodeBadFrontmatter, "frontmatter block larger than %d bytes", maxFrontmatterBytes)
}

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
	if len(y) > maxFrontmatterBytes {
		return nil, errFrontmatterTooLarge()
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

var dateLike = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// valueNode encodes one frontmatter value. Date-shaped strings get an
// untagged plain node so they are written as 2026-10-02, not "2026-10-02".
func valueNode(val any) (*yaml.Node, error) {
	if s, ok := val.(string); ok && dateLike.MatchString(s) {
		return &yaml.Node{Kind: yaml.ScalarNode, Value: s}, nil
	}
	n := &yaml.Node{}
	if err := n.Encode(val); err != nil {
		return nil, err
	}
	return n, nil
}

// decodeFrontmatterNode parses y into a node tree. Node decoding keeps
// anchors and aliases as written, so nothing is expanded. A second YAML
// document is refused: rewriting would silently drop it.
func decodeFrontmatterNode(y string) (yaml.Node, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(y))
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return doc, errf(CodeBadFrontmatter, "frontmatter is not valid YAML: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return doc, errf(CodeBadFrontmatter, "frontmatter holds more than one YAML document")
	}
	return doc, nil
}

// setFrontmatter merges fields into the note's frontmatter. Existing keys
// keep their position, comments, and flow style; new keys are appended in
// sorted order; a nil value removes the key. The body is never modified.
// A leading BOM stays first, and the rewritten block keeps the line ending
// style of the opening "---" line (LF when the note has no frontmatter).
func setFrontmatter(content string, fields map[string]any) (string, error) {
	y, body, ok, err := splitFrontmatter(content)
	if err != nil {
		return "", err
	}
	// Refuse before decoding; the final parseFrontmatter check below also
	// refuses a merge that would grow the block past the cap.
	if len(y) > maxFrontmatterBytes {
		return "", errFrontmatterTooLarge()
	}
	bom := ""
	if strings.HasPrefix(content, "\uFEFF") {
		bom = "\uFEFF"
		if !ok {
			body = strings.TrimPrefix(body, bom)
		}
	}
	eol := "\n"
	if ok && strings.HasPrefix(strings.TrimPrefix(content, bom), "---\r\n") {
		eol = "\r\n"
	}
	var doc yaml.Node
	if ok && strings.TrimSpace(y) != "" {
		if doc, err = decodeFrontmatterNode(y); err != nil {
			return "", err
		}
	}
	var m *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		m = doc.Content[0]
	} else {
		m = &yaml.Node{Kind: yaml.MappingNode}
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{m}}
	}
	if m.Kind != yaml.MappingNode {
		return "", errf(CodeBadFrontmatter, "frontmatter must be a YAML mapping")
	}
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		i := -1
		for j := 0; j+1 < len(m.Content); j += 2 {
			if kn := m.Content[j]; kn.Kind == yaml.ScalarNode && kn.Value == k {
				i = j
				break
			}
		}
		if fields[k] == nil {
			if i >= 0 {
				m.Content = slices.Delete(m.Content, i, i+2)
			}
			continue
		}
		vn, err := valueNode(fields[k])
		if err != nil {
			return "", errf(CodeBadFrontmatter, "field %q: %v", k, err)
		}
		if i >= 0 {
			if m.Content[i+1].Style&yaml.FlowStyle != 0 && vn.Kind == yaml.SequenceNode {
				vn.Style = yaml.FlowStyle
			}
			m.Content[i+1] = vn
			continue
		}
		// Encode the key too, so one that needs quoting ("true", "a: b")
		// is quoted.
		kn := &yaml.Node{}
		if err := kn.Encode(k); err != nil {
			return "", errf(CodeBadFrontmatter, "field %q: %v", k, err)
		}
		m.Content = append(m.Content, kn, vn)
	}
	if len(m.Content) == 0 {
		// A body that itself opens with a fence would be read as the
		// frontmatter once ours is gone: keep an empty block in front.
		if _, _, bok, berr := splitFrontmatter(body); bok || berr != nil {
			return bom + "---" + eol + "---" + eol + body, nil
		}
		return bom + body, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", errf(CodeBadFrontmatter, "cannot encode frontmatter: %v", err)
	}
	if err := enc.Close(); err != nil {
		return "", errf(CodeBadFrontmatter, "cannot encode frontmatter: %v", err)
	}
	block := buf.String()
	if eol != "\n" {
		block = strings.ReplaceAll(block, "\n", eol)
	}
	out := bom + "---" + eol + block + "---" + eol + body
	// read_note must be able to read what we write. Validating with the
	// reader's own parser also refuses what a merge can break or never
	// fixed: duplicate keys, complex keys, an anchor removed while an alias
	// still uses it.
	if _, err := parseFrontmatter(out); err != nil {
		return "", errf(CodeBadFrontmatter, "the update would leave frontmatter that cannot be read: %v", err)
	}
	return out, nil
}

// UpdateFrontmatter merges fields into a note's frontmatter without
// touching its body. Requires the version from the caller's last read.
func (v *Vault) UpdateFrontmatter(rel string, fields map[string]any, ver string) (string, error) {
	if len(fields) == 0 {
		return "", errf(CodeInvalidInput, "no fields to update")
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return "", errf(CodeInvalidInput, "fields are not serialisable: %v", err)
	}
	if err := v.checkSize(len(raw)); err != nil {
		return "", err
	}
	return v.modify(rel, ver, true, func(c string) (string, error) { return setFrontmatter(c, fields) })
}
