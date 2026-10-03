// Command thirdpartynotices writes THIRD_PARTY_NOTICES to stdout: the licence
// and notice files of the Go standard library and of every module linked into
// a release binary of cortex-mcp, reproduced in full.
//
//	go run ./tools/thirdpartynotices > THIRD_PARTY_NOTICES
//
// It asks the go command which packages ./cmd/cortex-mcp links for each
// release target (the module set differs between operating systems) and
// copies, for each module, the notice files in its root and in the directory
// of every linked package up to that root, so a licence that covers only a
// vendored subpackage is not missed. It uses only the standard library, so
// it adds nothing to go.mod; CI regenerates the file and fails on any diff.
//
// google/go-licenses was considered: it keeps one licence file per module
// and drops NOTICE, PATENTS, and the extra licence files some modules ship
// (zitadel's NOTICE, SQLite's), which a binary distribution has to carry.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// targets are the GOOS/GOARCH pairs .goreleaser.yaml builds. Keep both lists
// in step: a target missing here can link a module the file does not cover.
var targets = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

const mainPackage = "./cmd/cortex-mcp"

// listModule and listPackage hold the fields of `go list -json` output this
// command reads.
type listModule struct {
	Path    string
	Version string
	Dir     string
	Main    bool
}

type listPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *listModule
}

// entry is one section of the output: a title and the notice files under
// Dir, as slash-separated paths relative to it.
type entry struct {
	Title string
	Path  string
	Dir   string
	Files []string
}

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "thirdpartynotices:", err)
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	goroot, err := goOutput(nil, "env", "GOROOT")
	if err != nil {
		return err
	}
	goroot = strings.TrimSpace(goroot)
	stdFiles, err := noticeFiles(goroot, goroot)
	if err != nil {
		return err
	}
	if !slices.Contains(stdFiles, "LICENSE") {
		// Some distribution packages of Go move LICENSE out of GOROOT; an
		// official toolchain (go.dev/dl, setup-go, GOTOOLCHAIN) has it.
		return fmt.Errorf("no LICENSE in GOROOT %s: run with an official Go toolchain", goroot)
	}
	std := entry{Title: "The Go standard library and runtime", Dir: goroot, Files: stdFiles}

	var pkgs []listPackage
	for _, t := range targets {
		env := []string{"GOOS=" + t.goos, "GOARCH=" + t.goarch, "CGO_ENABLED=0"}
		out, err := goOutput(env, "list", "-deps", "-json=ImportPath,Dir,Standard,Module", mainPackage)
		if err != nil {
			return err
		}
		p, err := decodePackages(strings.NewReader(out))
		if err != nil {
			return fmt.Errorf("go list for %s/%s: %w", t.goos, t.goarch, err)
		}
		pkgs = append(pkgs, p...)
	}
	mods, err := collect(pkgs)
	if err != nil {
		return err
	}
	return render(w, std, mods)
}

// goOutput runs the go command with fixed arguments and returns its stdout.
func goOutput(env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...) // #nosec G204 -- the arguments are constants of this program, not input
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// decodePackages reads the stream of JSON objects `go list -json` prints.
func decodePackages(r io.Reader) ([]listPackage, error) {
	dec := json.NewDecoder(r)
	var pkgs []listPackage
	for {
		var p listPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

// collect returns one entry per third-party module in pkgs, sorted by module
// path, with the notice files of the module root and of each linked package's
// directory chain up to it. A module without any licence file is an error:
// it cannot be redistributed until someone has looked at it.
func collect(pkgs []listPackage) ([]entry, error) {
	type found struct {
		e     entry
		files map[string]bool
		dirs  map[string]bool
	}
	byPath := map[string]*found{}
	for _, p := range pkgs {
		if p.Standard {
			continue
		}
		if p.Module == nil {
			return nil, fmt.Errorf("package %s has no module", p.ImportPath)
		}
		if p.Module.Main {
			continue
		}
		f := byPath[p.Module.Path]
		if f == nil {
			f = &found{
				e:     entry{Title: p.Module.Path + " " + p.Module.Version, Path: p.Module.Path, Dir: p.Module.Dir},
				files: map[string]bool{},
				dirs:  map[string]bool{},
			}
			byPath[p.Module.Path] = f
		}
		rel, err := filepath.Rel(f.e.Dir, p.Dir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("package %s is outside its module directory %s", p.ImportPath, f.e.Dir)
		}
		// Walk from the package directory up to the module root, inclusive.
		for dir := p.Dir; ; dir = filepath.Dir(dir) {
			if !f.dirs[dir] {
				f.dirs[dir] = true
				names, err := noticeFiles(f.e.Dir, dir)
				if err != nil {
					return nil, err
				}
				for _, n := range names {
					f.files[n] = true
				}
			}
			if dir == f.e.Dir {
				break
			}
		}
	}
	entries := make([]entry, 0, len(byPath))
	for _, f := range byPath {
		if len(f.files) == 0 {
			return nil, fmt.Errorf("module %s has no licence file", f.e.Title)
		}
		for n := range f.files {
			f.e.Files = append(f.e.Files, n)
		}
		sortFiles(f.e.Files)
		entries = append(entries, f.e)
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.Path, b.Path) })
	return entries, nil
}

// noticeFiles lists the notice files directly in dir, as slash-separated
// paths relative to root.
func noticeFiles(root, dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, de := range des {
		if !de.Type().IsRegular() || !isNoticeFile(de.Name()) {
			continue
		}
		rel, err := filepath.Rel(root, filepath.Join(dir, de.Name()))
		if err != nil {
			return nil, err
		}
		names = append(names, filepath.ToSlash(rel))
	}
	return names, nil
}

// isNoticeFile reports whether name looks like a licence or notice file:
// a known stem (LICENSE, LICENSE-SQLITE, NOTICE, ...) and either no extension
// or a plain-text one. Source files such as license.go are not notices.
func isNoticeFile(name string) bool {
	stem, ext, _ := strings.Cut(name, ".")
	switch strings.ToLower(ext) {
	case "", "txt", "md", "markdown", "rst":
	default:
		return false
	}
	stem = strings.ToUpper(stem)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "PATENTS", "UNLICENSE"} {
		if strings.HasPrefix(stem, prefix) {
			return true
		}
	}
	return false
}

// sortFiles orders a module's files with those in its root first, then by
// path, so the main licence leads each section.
func sortFiles(files []string) {
	slices.SortFunc(files, func(a, b string) int {
		if da, db := strings.Count(a, "/"), strings.Count(b, "/"); da != db {
			return da - db
		}
		return strings.Compare(a, b)
	})
}

const header = `Third-party notices for cortex-mcp

cortex-mcp is licensed under the PolyForm Noncommercial License 1.0.0 (see
LICENSE). Its release binaries and container image also contain the software
listed below, each under its own licence, reproduced in full in this file.

This file is generated from the packages linked into ./cmd/cortex-mcp for
every release target, with:

    go run ./tools/thirdpartynotices > THIRD_PARTY_NOTICES

Do not edit it by hand; CI fails when it is out of date.

Contents:
`

const rule = "================================================================================"

// render writes the header, the table of contents, and every file of std and
// mods. Line endings are normalized to LF and each file ends with exactly one
// newline, so the output does not depend on how a module was checked in.
func render(w io.Writer, std entry, mods []entry) error {
	all := append([]entry{std}, mods...)
	var b strings.Builder
	b.WriteString(header)
	for _, e := range all {
		fmt.Fprintf(&b, "  %s\n", e.Title)
	}
	for _, e := range all {
		fmt.Fprintf(&b, "\n%s\n%s\n%s\n", rule, e.Title, rule)
		for _, name := range e.Files {
			data, err := os.ReadFile(filepath.Join(e.Dir, filepath.FromSlash(name))) // #nosec G304 -- a notice file found under a module or GOROOT directory the go command reported
			if err != nil {
				return err
			}
			text := strings.ReplaceAll(string(data), "\r\n", "\n")
			text = strings.TrimRight(text, "\n \t") + "\n"
			fmt.Fprintf(&b, "\n--- %s ---\n%s", name, text)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
