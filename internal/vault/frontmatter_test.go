package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSplitFrontmatter(t *testing.T) {
	cases := []struct {
		name, in, yaml, body string
		ok                   bool
		code                 Code
	}{
		{"none", "# Title\n", "", "# Title\n", false, ""},
		{"basic", "---\na: 1\n---\nbody\n", "a: 1\n", "body\n", true, ""},
		{"crlf", "---\r\na: 1\r\n---\r\nbody", "a: 1\r\n", "body", true, ""},
		{"bom", "\uFEFF---\na: 1\n---\n", "a: 1\n", "", true, ""},
		{"empty", "---\n---\nbody", "", "body", true, ""},
		{"closing at end of file", "---\na: 1\n---", "a: 1\n", "", true, ""},
		{"unclosed", "---\na: 1\n", "", "", false, CodeBadFrontmatter},
		{"only opener", "---", "", "", false, CodeBadFrontmatter},
	}
	for _, c := range cases {
		y, body, ok, err := splitFrontmatter(c.in)
		if CodeOf(err) != c.code || y != c.yaml || body != c.body || ok != c.ok {
			t.Errorf("%s: got (%q, %q, %v, %v), want (%q, %q, %v, code %q)", c.name, y, body, ok, err, c.yaml, c.body, c.ok, c.code)
		}
	}
}

func FuzzSplitFrontmatter(f *testing.F) {
	for _, s := range []string{"", "---", "---\n---\n", "---\na: 1\n---\nb", "\uFEFF---\r\nx\r\n---"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, body, ok, err := splitFrontmatter(s)
		if err != nil {
			return
		}
		if !ok && body != s {
			t.Fatalf("no frontmatter but body %q != input %q", body, s)
		}
		if ok && !strings.HasSuffix(s, body) {
			t.Fatalf("body %q is not a suffix of %q", body, s)
		}
	})
}

func TestParseFrontmatterKeepsDatesAsStrings(t *testing.T) {
	m, err := parseFrontmatter("---\ncreated: 2026-10-01\nat: 2026-10-01T10:30:00Z\nnested: {d: 2026-01-02}\nlist: [2026-01-03, x]\n---\n")
	if err != nil {
		t.Fatal(err)
	}
	if m["created"] != "2026-10-01" || m["at"] != "2026-10-01T10:30:00Z" {
		t.Fatalf("m = %#v", m)
	}
	if m["nested"].(map[string]any)["d"] != "2026-01-02" || m["list"].([]any)[0] != "2026-01-03" {
		t.Fatalf("nested dates not converted: %#v", m)
	}
}

func FuzzParseFrontmatter(f *testing.F) {
	for _, s := range []string{"", "---\na: 1\n---\n", "---\na: {1: x, d: 2026-01-02}\n---\n", "---\n&a [*a]\n---\n", "---\n? [1]\n: x\n---\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m, err := parseFrontmatter(s)
		if err != nil {
			return
		}
		if _, err := json.Marshal(m); err != nil {
			t.Fatalf("frontmatter of %q is not JSON-safe: %v", s, err)
		}
	})
}

func TestParseFrontmatterNonFiniteFloatsAreJSONSafe(t *testing.T) {
	m, err := parseFrontmatter("---\na: .nan\nb: .inf\nc: [-.inf]\n---\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(m); err != nil {
		t.Fatalf("not JSON-safe: %v (%#v)", err, m)
	}
}

func TestSetFrontmatterMergesAndKeepsOrderAndComments(t *testing.T) {
	in := "---\ntype: note # kind of page\nstatus: draft\ntags: [kind/note, topic/dev]\ncreated: 2026-10-01\n---\n# Body\n"
	out, err := setFrontmatter(in, map[string]any{
		"status":  "active",
		"updated": "2026-10-02",
		"tags":    []any{"kind/note", "topic/tech"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "---\ntype: note # kind of page\nstatus: active\ntags: [kind/note, topic/tech]\ncreated: 2026-10-01\nupdated: 2026-10-02\n---\n# Body\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestSetFrontmatterRemovesAddsAndQuotesWhenNeeded(t *testing.T) {
	out, err := setFrontmatter("# Body\n", map[string]any{"type": "note", "flag": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "---\nflag: \"true\"\ntype: note\n---\n# Body\n" {
		t.Fatalf("got %q", out)
	}
	out, err = setFrontmatter("---\na: 1\nb: 2\n---\nx", map[string]any{"a": nil})
	if err != nil || out != "---\nb: 2\n---\nx" {
		t.Fatalf("remove: got %q, %v", out, err)
	}
	out, err = setFrontmatter("---\na: 1\n---\nx", map[string]any{"a": nil})
	if err != nil || out != "x" {
		t.Fatalf("remove last key: got %q, %v", out, err)
	}
}

func TestSetFrontmatterRejectsNonMapping(t *testing.T) {
	_, err := setFrontmatter("---\n- a\n---\n", map[string]any{"x": 1})
	wantCode(t, err, CodeBadFrontmatter)
}

func TestSetFrontmatterKeepsLineEndingsAndBOM(t *testing.T) {
	out, err := setFrontmatter("\uFEFF---\r\na: 1\r\n---\r\nbody\r\n", map[string]any{"b": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "\uFEFF---\r\na: 1\r\nb: x\r\n---\r\nbody\r\n"; out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	// No frontmatter yet: the BOM stays first, the block follows it.
	out, err = setFrontmatter("\uFEFF# T\n", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := "\uFEFF---\na: 1\n---\n# T\n"; out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestSetFrontmatterNeverTouchesBody(t *testing.T) {
	body := "# T\n---\nnot: frontmatter\n---\r\n\ttabs  \n\n---"
	out, err := setFrontmatter("---\na: 1\n---\n"+body, map[string]any{"a": 2, "b": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "\n---\n"+body) {
		t.Fatalf("body changed: %q", out)
	}
}

func TestSetFrontmatterRemovingAllKeysKeepsBodyABody(t *testing.T) {
	// A body that opens with a fence must not become frontmatter.
	in := "---\na: 1\n---\n---\nb: 2\n---\nx"
	out, err := setFrontmatter(in, map[string]any{"a": nil})
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok, err := splitFrontmatter(out)
	if err != nil || !ok || body != "---\nb: 2\n---\nx" {
		t.Fatalf("out %q: body %q ok %v err %v", out, body, ok, err)
	}
}

func TestSetFrontmatterValueShapes(t *testing.T) {
	out, err := setFrontmatter("---\na: 1\n---\n", map[string]any{
		"nested": map[string]any{"k": []any{"x", map[string]any{"d": "2026-01-02"}}},
		"a b":    "c: d",
		"true":   1,
		"multi":  "l1\nl2",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseFrontmatter(out)
	if err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, out)
	}
	if m["a b"] != "c: d" || m["multi"] != "l1\nl2" || m["true"] != 1 {
		t.Fatalf("m = %#v\n%s", m, out)
	}
	if n, _ := m["nested"].(map[string]any); n == nil || n["k"] == nil {
		t.Fatalf("nested lost: %#v", m)
	}
}

func TestSetFrontmatterAnchorsAndAliases(t *testing.T) {
	in := "---\nbase: &b {x: 1}\nuse: *b\nother: &o 5\n---\nbody"
	// Changing an unrelated key keeps anchors and aliases as written.
	out, err := setFrontmatter(in, map[string]any{"new": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "---\nbase: &b {x: 1}\nuse: *b\nother: &o 5\nnew: v\n---\nbody"; out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	// Removing or replacing an anchor that an alias still uses would write
	// an invalid document: refuse instead of corrupting the note.
	for _, f := range []map[string]any{{"base": nil}, {"base": "z"}} {
		_, err = setFrontmatter(in, f)
		wantCode(t, err, CodeBadFrontmatter)
	}
}

func TestSetFrontmatterRejectsMultipleDocuments(t *testing.T) {
	_, err := setFrontmatter("---\na: 1\n--- \nb: 2\n---\nx", map[string]any{"c": 1})
	wantCode(t, err, CodeBadFrontmatter)
}

func FuzzSetFrontmatter(f *testing.F) {
	for _, s := range []string{"", "x", "---\na: 1\n---\nb", "---\n---\n---\nz: 1\n---\n", "\uFEFF---\r\nx: &a 1\r\ny: *a\r\n---\r\nq", "---\n- a\n---\n"} {
		f.Add(s, "k", "v", false)
		f.Add(s, "a", "2026-10-02", true)
	}
	f.Fuzz(func(t *testing.T, content, key, val string, remove bool) {
		var fields map[string]any
		if remove {
			fields = map[string]any{key: nil}
		} else {
			fields = map[string]any{key: val, "tags": []any{val}}
		}
		out, err := setFrontmatter(content, fields)
		if err != nil {
			return
		}
		_, wantBody, ok, serr := splitFrontmatter(content)
		if serr != nil {
			t.Fatalf("setFrontmatter accepted unsplittable input %q", content)
		}
		if !ok {
			wantBody = strings.TrimPrefix(content, "\uFEFF")
		}
		_, gotBody, gok, err := splitFrontmatter(out)
		if err != nil {
			t.Fatalf("result %q does not split: %v", out, err)
		}
		if gok {
			if _, err := parseFrontmatter(out); err != nil {
				t.Fatalf("result %q frontmatter does not parse: %v", out, err)
			}
		} else {
			gotBody = strings.TrimPrefix(out, "\uFEFF")
		}
		if gotBody != wantBody {
			t.Fatalf("body changed: %q -> %q (out %q)", wantBody, gotBody, out)
		}
	})
}

func TestUpdateFrontmatterOnVault(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "---\nstatus: draft\n---\nbody\n")
	_, err := v.UpdateFrontmatter("a.md", map[string]any{}, "x")
	wantCode(t, err, CodeInvalidInput)
	n, _ := v.Read("a.md")
	if _, err := v.UpdateFrontmatter("a.md", map[string]any{"status": "done"}, n.Version); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "a.md"); got != "---\nstatus: done\n---\nbody\n" {
		t.Fatalf("content = %q", got)
	}
	_, err = v.UpdateFrontmatter("a.md", map[string]any{"status": "x"}, n.Version)
	wantCode(t, err, CodeChanged)
}

func TestSetFrontmatterRefusesWhatReadNoteCannotParse(t *testing.T) {
	for _, in := range []string{
		"---\na: 1\na: 2\n---\nx",
		"---\n? [a]\n: 1\n---\nx",
	} {
		_, err := setFrontmatter(in, map[string]any{"b": 1})
		wantCode(t, err, CodeBadFrontmatter)

		v, dir := newTestVault(t, Options{})
		writeFile(t, dir, "a.md", in)
		n, _ := v.Read("a.md")
		_, err = v.UpdateFrontmatter("a.md", map[string]any{"b": 1}, n.Version)
		wantCode(t, err, CodeBadFrontmatter)
		if got := readFile(t, dir, "a.md"); got != in {
			t.Fatalf("note changed: %q", got)
		}
	}
}

func TestSetFrontmatterEncodesJSONShapedValues(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"whole float", float64(3), "v: 3\n"},
		{"fraction", 0.1, "v: 0.1\n"},
		{"large", 1e21, "v: 1e+21\n"},
		{"nested null", map[string]any{"k": nil, "j": 1}, "v:\n  j: 1\n  k: null\n"},
		{"mixed list", []any{"a", float64(1), true, nil, "2026-10-02"}, "v:\n  - a\n  - 1\n  - true\n  - null\n  - \"2026-10-02\"\n"},
	}
	for _, c := range cases {
		out, err := setFrontmatter("", map[string]any{"v": c.val})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := "---\n" + c.want + "---\n"; out != want {
			t.Errorf("%s: got %q, want %q", c.name, out, want)
		}
	}
}
