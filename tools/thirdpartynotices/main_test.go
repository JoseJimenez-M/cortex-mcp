package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsNoticeFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"LICENSE", true},
		{"LICENSE.txt", true},
		{"License.md", true},
		{"LICENCE", true},
		{"LICENSE-3RD-PARTY.md", true},
		{"LICENSE-SQLITE", true},
		{"COPYING", true},
		{"COPYRIGHT", true},
		{"NOTICE", true},
		{"NOTICE.txt", true},
		{"PATENTS", true},
		{"UNLICENSE", true},
		{"license.go", false},
		{"licenses_test.go", false},
		{"LICENSE.html", false},
		{"README.md", false},
		{"AUTHORS", false},
		{"notices.json", false},
	}
	for _, tt := range tests {
		if got := isNoticeFile(tt.name); got != tt.want {
			t.Errorf("isNoticeFile(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDecodePackages(t *testing.T) {
	stream := `{"ImportPath":"fmt","Dir":"/goroot/src/fmt","Standard":true}
{"ImportPath":"example.com/a/sub","Dir":"/mod/a/sub","Module":{"Path":"example.com/a","Version":"v1.2.3","Dir":"/mod/a"}}
`
	pkgs, err := decodePackages(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if !pkgs[0].Standard || pkgs[0].Module != nil {
		t.Errorf("first package = %+v, want a standard package without module", pkgs[0])
	}
	m := pkgs[1].Module
	if m == nil || m.Path != "example.com/a" || m.Version != "v1.2.3" || m.Dir != "/mod/a" {
		t.Errorf("second package module = %+v", m)
	}
	if _, err := decodePackages(strings.NewReader(`{"ImportPath":`)); err == nil {
		t.Error("truncated stream: want an error")
	}
}

// writeFiles creates each path (slash-separated, relative to root) with its
// content.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollect(t *testing.T) {
	root := t.TempDir()
	modA := filepath.Join(root, "a")
	modB := filepath.Join(root, "b")
	writeFiles(t, root, map[string]string{
		"a/LICENSE":           "a licence",
		"a/NOTICE":            "a notice",
		"a/README.md":         "not a notice",
		"a/sub/LICENSE.txt":   "sub licence",
		"a/sub/license.go":    "package sub",
		"a/sub/deep/x.go":     "package deep",
		"a/unlinked/LICENSE":  "never linked",
		"b/COPYING":           "b licence",
		"main/LICENSE":        "the main module's own licence",
		"main/cmd/app/app.go": "package main",
	})
	modAInfo := &listModule{Path: "example.com/a", Version: "v1.0.0", Dir: modA}
	// Two targets list overlapping packages; b is linked by one target only.
	pkgs := []listPackage{
		{ImportPath: "fmt", Dir: "/goroot/src/fmt", Standard: true},
		{ImportPath: "example.com/main/cmd/app", Dir: filepath.Join(root, "main", "cmd", "app"),
			Module: &listModule{Path: "example.com/main", Main: true, Dir: filepath.Join(root, "main")}},
		{ImportPath: "example.com/a/sub/deep", Dir: filepath.Join(modA, "sub", "deep"), Module: modAInfo},
		{ImportPath: "example.com/a", Dir: modA, Module: modAInfo},
		{ImportPath: "example.com/a/sub/deep", Dir: filepath.Join(modA, "sub", "deep"), Module: modAInfo},
		{ImportPath: "example.com/b", Dir: modB, Module: &listModule{Path: "example.com/b", Version: "v0.1.0", Dir: modB}},
	}
	mods, err := collect(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 {
		t.Fatalf("got %d modules, want 2: %+v", len(mods), mods)
	}
	if mods[0].Path != "example.com/a" || mods[1].Path != "example.com/b" {
		t.Errorf("modules not sorted by path: %s, %s", mods[0].Path, mods[1].Path)
	}
	wantA := []string{"LICENSE", "NOTICE", "sub/LICENSE.txt"}
	if got := strings.Join(mods[0].Files, ","); got != strings.Join(wantA, ",") {
		t.Errorf("module a files = %v, want %v", mods[0].Files, wantA)
	}
	if got := strings.Join(mods[1].Files, ","); got != "COPYING" {
		t.Errorf("module b files = %v, want [COPYING]", mods[1].Files)
	}
}

func TestCollectErrors(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"bare/x.go":  "package bare",
		"ok/LICENSE": "ok",
		"other/y.go": "package other",
		"nomod/z.go": "package nomod",
	})
	tests := []struct {
		name string
		pkg  listPackage
		want string
	}{
		{
			name: "module without any licence file",
			pkg: listPackage{ImportPath: "example.com/bare", Dir: filepath.Join(root, "bare"),
				Module: &listModule{Path: "example.com/bare", Version: "v1.0.0", Dir: filepath.Join(root, "bare")}},
			want: "no licence file",
		},
		{
			name: "package outside its module directory",
			pkg: listPackage{ImportPath: "example.com/ok/sub", Dir: filepath.Join(root, "other"),
				Module: &listModule{Path: "example.com/ok", Version: "v1.0.0", Dir: filepath.Join(root, "ok")}},
			want: "outside its module",
		},
		{
			name: "non-standard package without a module",
			pkg:  listPackage{ImportPath: "nomod", Dir: filepath.Join(root, "nomod")},
			want: "no module",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := collect([]listPackage{tt.pkg})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("collect() error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestRender(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go/LICENSE":    "Go licence\n",
		"go/PATENTS":    "Go patents",
		"a/LICENSE":     "line one\r\nline two\r\n\r\n\r\n",
		"a/sub/LICENSE": "sub",
	})
	std := entry{Title: "The Go standard library and runtime", Dir: filepath.Join(root, "go"), Files: []string{"LICENSE", "PATENTS"}}
	mods := []entry{{Title: "example.com/a v1.0.0", Path: "example.com/a", Dir: filepath.Join(root, "a"), Files: []string{"LICENSE", "sub/LICENSE"}}}
	var buf bytes.Buffer
	if err := render(&buf, std, mods); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"cortex-mcp is licensed under the PolyForm Noncommercial License 1.0.0",
		"go run ./tools/thirdpartynotices",
		"  The Go standard library and runtime\n  example.com/a v1.0.0\n",
		"--- LICENSE ---\nGo licence\n\n--- PATENTS ---\nGo patents\n",
		"\nexample.com/a v1.0.0\n",
		"--- LICENSE ---\nline one\nline two\n\n--- sub/LICENSE ---\nsub\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Error("output keeps carriage returns")
	}
	if !strings.HasSuffix(out, "sub\n") {
		t.Errorf("output does not end with the last file and one newline: %q", out[len(out)-10:])
	}
	if strings.Index(out, "Go licence") > strings.Index(out, "line one") {
		t.Error("the standard library must come before the modules")
	}
}
