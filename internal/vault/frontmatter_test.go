package vault

import (
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
