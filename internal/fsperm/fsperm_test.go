package fsperm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivateDirOnFreshDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateFileMissingIsNotAnError(t *testing.T) {
	if err := PrivateFile(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
}

func TestUnixModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // deliberately loose
		t.Fatal(err)
	}
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil { //nolint:gosec // deliberately loose
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := PrivateFile(f); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, f: 0o600} {
		if info, _ := os.Stat(p); info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", filepath.Base(p), info.Mode().Perm(), want)
		}
	}
}

func TestSharedDirsAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	for name, mode := range map[string]os.FileMode{
		"sticky":         0o777 | os.ModeSticky,
		"world-writable": 0o777,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, mode); err != nil { //nolint:gosec // simulates a shared dir
				t.Fatal(err)
			}
			err := PrivateDir(dir)
			if err == nil || !strings.Contains(err.Error(), "shared directory") {
				t.Fatalf("err = %v, want shared directory", err)
			}
			info, _ := os.Stat(dir)
			if info.Mode() != mode|os.ModeDir {
				t.Errorf("mode changed to %v", info.Mode())
			}
		})
	}
}
