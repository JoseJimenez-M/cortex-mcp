package vault

import (
	"slices"
	"strings"
	"testing"
)

func TestParseHeadingsSkipsFrontmatterAndCode(t *testing.T) {
	content := "---\ntitle: x\n# not a heading\n---\n# Top\ntext #tag\n```\n# code\n```\n## Sub ##\n#nospace\n    # indented code\n### Learn C#\n"
	got := parseHeadings(strings.Split(content, "\n"))
	want := []heading{{4, 1, "Top"}, {9, 2, "Sub"}, {12, 3, "Learn C#"}}
	if !slices.Equal(got, want) {
		t.Fatalf("parseHeadings = %+v, want %+v", got, want)
	}
}

func TestParseHeadingsEdgeCases(t *testing.T) {
	cases := []struct {
		name, content string
		want          []heading
	}{
		{"longer fence is not closed by a shorter one",
			"````\n# a\n```\n# b\n````\n# real\n", []heading{{5, 1, "real"}}},
		{"longer closing fence is fine",
			"```\n# a\n`````\n# real\n", []heading{{3, 1, "real"}}},
		{"fence char must match",
			"```\n# a\n~~~\n# b\n```\n# real\n", []heading{{5, 1, "real"}}},
		{"closing fence has no info string",
			"```\n# a\n```go\n# b\n```\n# real\n", []heading{{5, 1, "real"}}},
		{"tilde fence",
			"~~~~\n# a\n~~~\n# b\n~~~~\n# real\n", []heading{{5, 1, "real"}}},
		{"backtick info string with backtick is not a fence",
			"``` a`b\n# real\n", []heading{{1, 1, "real"}}},
		{"unclosed fence swallows the rest",
			"# a\n```\n# b\n", []heading{{0, 1, "a"}}},
		{"setext underline is not a heading and not frontmatter",
			"# A\nSetext\n---\n# B\n===\n", []heading{{0, 1, "A"}, {3, 1, "B"}}},
		{"empty heading text",
			"#\n## \n### ###\n# x\n", []heading{{0, 1, ""}, {1, 2, ""}, {2, 3, ""}, {3, 1, "x"}}},
		{"seven hashes",
			"####### seven\n###### six\n", []heading{{1, 6, "six"}}},
		{"CRLF",
			"---\r\na: b\r\n---\r\n# A\r\n```\r\n# c\r\n```\r\n## B ##\r\n", []heading{{3, 1, "A"}, {7, 2, "B"}}},
		{"BOM before frontmatter",
			"\uFEFF---\na: b\n# no\n---\n# A\n", []heading{{4, 1, "A"}}},
		{"BOM on a heading in line 0",
			"\uFEFF# A\n## B\n", []heading{{0, 1, "A"}, {1, 2, "B"}}},
		{"blockquote is not a heading (unsupported)",
			"> # quoted\n", nil},
		{"unclosed frontmatter marker is just text",
			"---\n# A\n", []heading{{1, 1, "A"}}},
	}
	for _, c := range cases {
		got := parseHeadings(strings.Split(c.content, "\n"))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestFindSection(t *testing.T) {
	lines := strings.Split("# A\na1\n## B\nb1\n\n## C\nc1\n# D\n", "\n")
	cases := []struct {
		title      string
		start, end int
	}{
		{"A", 0, 7}, {"B", 2, 5}, {"## C", 5, 7}, {"D", 7, 9},
	}
	for _, c := range cases {
		s, e, err := findSection(lines, c.title)
		if err != nil || s != c.start || e != c.end {
			t.Errorf("findSection(%q) = %d, %d, %v; want %d, %d", c.title, s, e, err, c.start, c.end)
		}
	}
	_, _, err := findSection(lines, "Missing")
	wantCode(t, err, CodeSectionNotFound)
	_, _, err = findSection(strings.Split("## X\n## X\n", "\n"), "X")
	wantCode(t, err, CodeSectionAmbiguous)
	// The same text at different levels is still ambiguous.
	_, _, err = findSection(strings.Split("# X\n## X\n", "\n"), "X")
	wantCode(t, err, CodeSectionAmbiguous)
	for _, empty := range []string{"", "  ", "##", "# "} {
		_, _, err = findSection(strings.Split("#\ntext\n", "\n"), empty)
		wantCode(t, err, CodeInvalidInput)
	}
}

func TestFindSectionCRLF(t *testing.T) {
	lines := strings.Split("# A\r\na\r\n## B\r\nb\r\n# C\r\n", "\n")
	s, e, err := findSection(lines, "A")
	if err != nil || s != 0 || e != 4 {
		t.Fatalf("findSection = %d, %d, %v", s, e, err)
	}
}

func TestAppendToSection(t *testing.T) {
	cases := []struct{ name, content, section, text, want string }{
		{"middle section", "# A\na1\n\n# B\nb1\n", "A", "new", "# A\na1\nnew\n\n# B\nb1\n"},
		{"last section", "# A\na1\n", "A", "new\n", "# A\na1\nnew\n"},
		{"empty section", "# A\n\n# B\n", "A", "x", "# A\nx\n\n# B\n"},
		{"after subsections", "# A\na\n## A1\nx\n# B\n", "A", "new", "# A\na\n## A1\nx\nnew\n# B\n"},
		{"no trailing newline", "# A\na", "A", "new", "# A\na\nnew"},
		{"CRLF note gets CRLF text", "# A\r\na\r\n\r\n# B\r\n", "A", "x\ny\n", "# A\r\na\r\nx\r\ny\r\n\r\n# B\r\n"},
		{"CRLF text in LF note is normalised", "# A\na\n", "A", "x\r\ny", "# A\na\nx\ny\n"},
		{"heading-like line in code is ignored", "# A\n```\n# B\n```\n# B\nb\n", "B", "n", "# A\n```\n# B\n```\n# B\nb\nn\n"},
	}
	for _, c := range cases {
		got, err := appendToSection(c.content, c.section, c.text)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestReplaceSection(t *testing.T) {
	cases := []struct{ name, content, section, body, want string }{
		{"keeps neighbours", "# A\nold\n\n# B\nb\n", "A", "new", "# A\nnew\n\n# B\nb\n"},
		{"keeps blank after heading", "# A\n\nold\n\n# B\n", "A", "new", "# A\n\nnew\n\n# B\n"},
		{"empty body clears", "# A\nold\n# B\n", "A", "", "# A\n# B\n"},
		{"last section", "# A\nold\n", "A", "new\n", "# A\nnew\n"},
		{"drops subsections", "# A\nold\n## A1\nx\n# B\n", "A", "new", "# A\nnew\n# B\n"},
		{"CRLF note", "# A\r\nold\r\n\r\n# B\r\n", "A", "x\ny", "# A\r\nx\r\ny\r\n\r\n# B\r\n"},
		{"CRLF keeps blank after heading", "# A\r\n\r\nold\r\n# B\r\n", "A", "new", "# A\r\n\r\nnew\r\n# B\r\n"},
	}
	for _, c := range cases {
		got, err := replaceSection(c.content, c.section, c.body)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestReplaceSectionNeedsCurrentVersion(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "# A\nold\n")
	_, err := v.ReplaceSection("a.md", "A", "new", "")
	wantCode(t, err, CodeVersionRequired)
	_, err = v.ReplaceSection("a.md", "A", "new", "0000000000000000")
	wantCode(t, err, CodeChanged)
	n, _ := v.Read("a.md")
	ver, err := v.ReplaceSection("a.md", "A", "new", n.Version)
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := v.Read("a.md")
	if n2.Content != "# A\nnew\n" || n2.Version != ver {
		t.Fatalf("after replace: %+v, returned version %q", n2, ver)
	}
}

func FuzzParseHeadings(f *testing.F) {
	for _, s := range []string{"# A\n## B", "---\n# x\n---\n# y", "```\n# no\n```", "####### seven", "# C# ##", "````\n```\n# a\n````", "#\r\n## ##\r\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lines := strings.Split(s, "\n")
		prev := -1
		for _, h := range parseHeadings(lines) {
			if h.line <= prev || strings.Contains(h.text, "\r") {
				t.Fatalf("headings not increasing or text has CR: %+v for %q", h, s)
			}
			prev = h.line
			if h.line < 0 || h.line >= len(lines) || h.level < 1 || h.level > 6 {
				t.Fatalf("bad heading %+v for %q", h, s)
			}
		}
	})
}

func TestAppendToSectionOnVault(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	writeFile(t, dir, "a.md", "# Tasks\n- one\n")
	if _, err := v.AppendToSection("a.md", "Tasks", "- two"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "a.md"); got != "# Tasks\n- one\n- two\n" {
		t.Fatalf("content = %q", got)
	}
	_, err := v.AppendToSection("a.md", "Nope", "x")
	wantCode(t, err, CodeSectionNotFound)
	_, err = v.AppendToSection("a.md", "Tasks", "  \n")
	wantCode(t, err, CodeInvalidInput)
}
