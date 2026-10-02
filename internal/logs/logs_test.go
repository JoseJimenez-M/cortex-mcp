package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestWriteAndReadSince(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	must(t, l.Write(Entry{Time: t0, Client: "muse", Tool: "create_note", Path: "a.md", Result: "ok"}))
	must(t, l.Write(Entry{Time: t0.Add(time.Hour), Client: "claude", Tool: "append", Path: "b.md", Result: "note_not_found"}))
	must(t, l.Close())
	got, err := ReadSince(dir, t0.Add(30*time.Minute))
	if err != nil || len(got) != 1 || got[0].Client != "claude" || !got[0].Time.Equal(t0.Add(time.Hour)) {
		t.Fatalf("ReadSince = %+v, %v", got, err)
	}
}

func TestTimestampIsUTCRFC3339(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, 1)
	loc := time.FixedZone("x", 2*3600)
	must(t, l.Write(Entry{Time: time.Date(2026, 10, 2, 14, 0, 0, 0, loc), Tool: "t"}))
	must(t, l.Close())
	b, _ := os.ReadFile(filepath.Join(dir, "writes.log"))
	if !strings.HasPrefix(string(b), "2026-10-02T12:00:00Z\t") {
		t.Fatalf("line = %q", b)
	}
}

func TestFieldsCannotForgeLines(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, 1)
	must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "append", Path: "a.md\n2026-01-01T00:00:00Z\tevil\tdelete_note\tx.md\tok", Result: "ok"}))
	must(t, l.Write(Entry{Time: time.Now(), Tool: "append"}))
	must(t, l.Close())
	b, _ := os.ReadFile(filepath.Join(dir, "writes.log"))
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("log has %d lines, want 2:\n%s", n, b)
	}
	got, _ := ReadSince(dir, time.Time{})
	if len(got) != 2 || got[1].Client != "-" || got[1].Path != "-" {
		t.Fatalf("entries = %+v", got)
	}
}

func TestFieldSanitizing(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty", "", "-"},
		{"tab and newline", "a\tb\nc\rd", "a b c d"},
		{"nul and esc", "a\x00b\x1bc", "a b c"},
		{"c1 next line", "a\u0085b", "a b"},
		{"rtl override (Cf)", "a\u202eb", "a b"},
		{"zero width (Cf)", "a\u200bb\ufeffc", "a b c"},
		{"line separator (Zl)", "a b", "a b"},
		{"paragraph separator (Zp)", "a b", "a b"},
		{"invalid utf8 (a run becomes one U+FFFD)", "a\xff\xfeb", "a\ufffdb"},
		{"plain unicode kept", "notas/ñandú.md", "notas/ñandú.md"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := field(tc.in); got != tc.want {
				t.Errorf("field(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFieldIsCappedAtRuneBoundary(t *testing.T) {
	got := field(strings.Repeat("a", 10000))
	if len(got) != maxFieldBytes+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("len = %d, want %d with ellipsis", len(got), maxFieldBytes+3)
	}
	// 3-byte runes: the cap must not split one.
	got = field(strings.Repeat("€", 1000))
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "...") || len(got) > maxFieldBytes+3 {
		t.Fatalf("bad cut: len %d valid %v", len(got), utf8.ValidString(got))
	}
	if short := field(strings.Repeat("a", maxFieldBytes)); strings.HasSuffix(short, "...") {
		t.Fatal("field at exactly the cap must not be cut")
	}
}

func TestHugeFieldIsCappedAndReadable(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, 1)
	must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: strings.Repeat("x", 200000), Result: "ok"}))
	must(t, l.Close())
	got, err := ReadSince(dir, time.Time{})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d entries, %v", len(got), err)
	}
}

func TestReadSinceSkipsOverLongLines(t *testing.T) {
	dir := t.TempDir()
	good := "2026-10-02T12:00:00Z\tc\tt\tp\tok\n"
	huge := strings.Repeat("y", 300000) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "writes.log"), []byte(good+huge+good), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSince(dir, time.Time{})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %d entries, %v; want the 2 good lines around the huge one", len(got), err)
	}
}

func TestReadSinceMissingDirAndMalformed(t *testing.T) {
	if got, err := ReadSince(filepath.Join(t.TempDir(), "nope"), time.Time{}); err != nil || len(got) != 0 {
		t.Fatalf("missing dir: %v, %v", got, err)
	}
	dir := t.TempDir()
	body := "garbage\nnot-a-time\tc\tt\tp\tok\n2026-10-02T12:00:00Z\tc\tt\tp\tok\n"
	_ = os.WriteFile(filepath.Join(dir, "writes.log"), []byte(body), 0o600)
	if got, _ := ReadSince(dir, time.Time{}); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestRotationKeepsAtMostKeepFiles(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 200, 2)
	for i := range 50 {
		must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "append", Path: fmt.Sprintf("note-%02d.md", i), Result: "ok"}))
	}
	must(t, l.Close())
	files, _ := filepath.Glob(filepath.Join(dir, "writes.log*"))
	if len(files) != 3 {
		t.Fatalf("files = %v, want writes.log plus 2 rotated", files)
	}
	for _, f := range files {
		if info, _ := os.Stat(f); info.Size() > 200 {
			t.Errorf("%s is %d bytes, over the 200 limit", f, info.Size())
		}
	}
	got, _ := ReadSince(dir, time.Time{})
	if len(got) == 0 || got[len(got)-1].Path != "note-49.md" {
		t.Fatalf("last entry = %+v", got[len(got)-1])
	}
	for i := 1; i < len(got); i++ {
		if got[i].Path < got[i-1].Path {
			t.Fatal("entries are not oldest first")
		}
	}
}

func TestRotationKeepOne(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 150, 1)
	for i := range 20 {
		must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: fmt.Sprintf("n%02d", i), Result: "ok"}))
	}
	must(t, l.Close())
	files, _ := filepath.Glob(filepath.Join(dir, "writes.log*"))
	if len(files) != 2 {
		t.Fatalf("files = %v, want writes.log and writes.log.1", files)
	}
}

func TestEntryLargerThanMaxBytes(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 10, 2)
	for i := range 5 {
		must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: fmt.Sprintf("n%d", i), Result: "ok"}))
	}
	must(t, l.Close())
	got, _ := ReadSince(dir, time.Time{})
	// keep=2 plus the live file: the last 3 survive, each alone in its file.
	if len(got) != 3 || got[2].Path != "n4" {
		t.Fatalf("entries = %+v", got)
	}
}

func TestOpenPrunesFilesBeyondKeepAndIgnoresStrangers(t *testing.T) {
	dir := t.TempDir()
	line := "2026-10-02T12:00:00Z\tc\tt\tp\tok\n"
	for _, n := range []string{"writes.log.1", "writes.log.2", "writes.log.3", "writes.log.bak"} {
		_ = os.WriteFile(filepath.Join(dir, n), []byte(line), 0o600)
	}
	l, err := Open(dir, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	must(t, l.Close())
	if _, err := os.Stat(filepath.Join(dir, "writes.log.3")); !os.IsNotExist(err) {
		t.Fatal("writes.log.3 should be pruned when keep=2")
	}
	if _, err := os.Stat(filepath.Join(dir, "writes.log.bak")); err != nil {
		t.Fatal("unrelated file must be left alone")
	}
	if got, _ := ReadSince(dir, time.Time{}); len(got) != 2 {
		t.Fatalf("ReadSince should read only .1 and .2, got %d", len(got))
	}
}

func TestOpenRejectsBadLimits(t *testing.T) {
	for _, tc := range []struct {
		max  int64
		keep int
	}{{0, 1}, {-1, 1}, {100, 0}, {100, -1}} {
		if l, err := Open(t.TempDir(), tc.max, tc.keep); err == nil {
			_ = l.Close()
			t.Errorf("Open(max=%d, keep=%d) should fail", tc.max, tc.keep)
		}
	}
}

func TestConcurrentWritesKeepEveryLine(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1000, 10000)
	const goroutines, each = 40, 25
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: fmt.Sprintf("g%d-%d", g, i), Result: "ok"}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	must(t, l.Close())
	got, err := ReadSince(dir, time.Time{})
	if err != nil || len(got) != goroutines*each {
		t.Fatalf("got %d entries, want %d (%v)", len(got), goroutines*each, err)
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	l, _ := Open(dir, 150, 2)
	for i := range 10 {
		must(t, l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: fmt.Sprintf("n%d", i), Result: "ok"}))
	}
	must(t, l.Close())
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", info.Mode().Perm())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "writes.log*"))
	if len(files) < 2 {
		t.Fatalf("expected rotation, files = %v", files)
	}
	for _, f := range files {
		if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", f, info.Mode().Perm())
		}
	}
}

func TestWriteAfterCloseErrorsAndDoubleCloseIsSafe(t *testing.T) {
	l, _ := Open(t.TempDir(), 1<<20, 1)
	must(t, l.Close())
	if err := l.Write(Entry{Time: time.Now(), Tool: "t"}); err == nil {
		t.Fatal("Write after Close must return an error")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteKeepsEntryWhenRotationFails(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 100, 2)
	// A non-empty directory in the oldest slot makes the rotation's Remove fail
	// (also as root).
	slot := filepath.Join(dir, "writes.log.2")
	must(t, os.MkdirAll(filepath.Join(slot, "x"), 0o700))
	var failed error
	for i := range 5 {
		if err := l.Write(Entry{Time: time.Now(), Client: "c", Tool: "t", Path: fmt.Sprintf("n%d", i), Result: "ok"}); err != nil {
			failed = err
			if !strings.Contains(readFile0(t, dir), fmt.Sprintf("n%d", i)) {
				t.Fatalf("entry n%d dropped despite rotation error", i)
			}
		}
	}
	if failed == nil {
		t.Fatal("expected a rotation error to be reported")
	}
	must(t, l.Close())
}

func readFile0(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "writes.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReadSinceIsInclusiveWithinTheSecond(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, 1)
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	must(t, l.Write(Entry{Time: t0.Add(400 * time.Millisecond), Tool: "t"}))
	must(t, l.Close())
	got, _ := ReadSince(dir, t0.Add(700*time.Millisecond))
	if len(got) != 1 {
		t.Fatalf("entry in the same second as since was dropped: %+v", got)
	}
}

func TestOpenTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	must(t, os.Mkdir(dir, 0o755))
	must(t, os.Chmod(dir, 0o755))
	f := filepath.Join(dir, "writes.log")
	must(t, os.WriteFile(f, nil, 0o644))
	must(t, os.Chmod(f, 0o644))
	l, err := Open(dir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	must(t, l.Close())
	for p, want := range map[string]os.FileMode{dir: 0o700, f: 0o600} {
		if info, _ := os.Stat(p); info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", p, info.Mode().Perm(), want)
		}
	}
}

func TestOpenRefusesSharedDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil { // #nosec G302 -- simulates a shared /tmp
		t.Fatal(err)
	}
	l, err := Open(dir, 1024, 2)
	if err == nil {
		_ = l.Close()
		t.Fatal("Open accepted a shared directory")
	}
	if !strings.Contains(err.Error(), "shared directory") {
		t.Errorf("error = %v", err)
	}
	info, _ := os.Stat(dir)
	if info.Mode()&os.ModeSticky == 0 || info.Mode().Perm() != 0o777 {
		t.Errorf("shared dir mode changed to %v", info.Mode())
	}
}

func TestOpenFreshChildOfTempDir(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "child"), 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
}

func TestOpenRequiresAbsoluteDir(t *testing.T) {
	if l, err := Open("relative-logs", 1024, 2); err == nil {
		_ = l.Close()
		t.Fatal("Open accepted a relative dir")
	}
}
