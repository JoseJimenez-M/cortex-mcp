// Package logs keeps an append-only, size-rotated log of vault writes.
//
// The log is operator-facing, not part of the vault. All file access goes
// through an os.Root on the log directory, so a name can never escape it.
package logs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	fileName = "writes.log"

	// maxFieldBytes caps each field so one huge path cannot bloat the log.
	// Five capped fields plus the timestamp stay far below maxLineBytes.
	maxFieldBytes = 512

	// maxLineBytes is the longest line ReadSince will parse; longer ones
	// (foreign or corrupted data, since Write never produces them) are skipped.
	maxLineBytes = 16 << 10
)

var errClosed = errors.New("logs: logger is closed")

// Entry is one write: who did what to which note, and how it ended.
type Entry struct {
	Time   time.Time
	Client string
	Tool   string
	Path   string
	Result string // "ok" or an error code
}

// Logger appends entries to <dir>/writes.log and rotates it by size.
type Logger struct {
	mu       sync.Mutex
	root     *os.Root
	maxBytes int64
	keep     int
	f        *os.File // nil after Close, or after a failed rotation (retried on next Write)
	closed   bool
	size     int64
}

// Open creates dir if needed (0700: the log reveals note names) and opens
// the log for appending. maxBytes and keep must be at least 1. Rotated files
// beyond keep, left by an earlier run with a larger keep, are removed so that
// ReadSince only ever sees what this configuration would retain.
func Open(dir string, maxBytes int64, keep int) (*Logger, error) {
	if maxBytes < 1 || keep < 1 {
		return nil, fmt.Errorf("logs: maxBytes and keep must be at least 1 (got %d, %d)", maxBytes, keep)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Never chmod a directory other users share (/tmp, a world-writable mount).
	if info, err := os.Stat(dir); err != nil {
		return nil, err
	} else if m := info.Mode(); m&os.ModeSticky != 0 || m.Perm()&0o002 != 0 {
		return nil, fmt.Errorf("state dir %s is a shared directory; use a dedicated one", dir)
	}
	// MkdirAll leaves an existing directory as it was; tighten it, and report
	// failure rather than run with a world-readable log.
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the owner x bit; 0700 is the tightest usable mode
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	l := &Logger{root: root, maxBytes: maxBytes, keep: keep}
	if names, err := rotatedNames(root); err == nil {
		for _, r := range names {
			if r.n > keep {
				_ = root.Remove(r.name)
			}
		}
	}
	if err := l.open(); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := l.f.Chmod(0o600); err != nil { // an existing file keeps its old mode otherwise
		_ = l.f.Close()
		_ = root.Close()
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := l.root.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.size = f, info.Size()
	return nil
}

// field keeps an entry on one line. Control characters (tab, newline, ...),
// format characters (Cf: bidi overrides, zero-width marks) and the Unicode
// line and paragraph separators (Zl, Zp: some viewers render them as line
// breaks) become spaces; invalid UTF-8 becomes U+FFFD. Without this, an
// assistant-chosen path could forge or visually disguise log lines.
func field(s string) string {
	if s == "" {
		return "-"
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return r
	}, s)
	if len(s) <= maxFieldBytes {
		return s
	}
	cut := maxFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// Write appends one entry, rotating first if it would exceed maxBytes.
// The timestamp is UTC RFC 3339 with second precision: entries within the
// same second are ordered by their position in the file, not by time.
// An entry larger than maxBytes is still written (alone in its file).
func (l *Logger) Write(e Entry) error {
	line := strings.Join([]string{
		e.Time.UTC().Format(time.RFC3339), field(e.Client), field(e.Tool), field(e.Path), field(e.Result),
	}, "\t") + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errClosed
	}
	if l.f == nil { // an earlier rotation failed to reopen
		if err := l.open(); err != nil {
			return err
		}
	}
	// size > 0 guarantees progress: an empty file is never rotated, so an
	// oversized entry cannot cause an endless rotate loop.
	var rotErr error
	if l.size > 0 && l.size+int64(len(line)) > l.maxBytes {
		rotErr = l.rotate()
		if l.f == nil { // could not reopen: nowhere to write
			return rotErr
		}
	}
	// A rotation error is reported, but the entry is still written: losing
	// audit data because housekeeping failed would be worse.
	n, err := l.f.WriteString(line)
	l.size += int64(n)
	return errors.Join(rotErr, err)
}

// rotate shifts writes.log.N up by one, drops the oldest beyond keep, and
// starts a fresh writes.log. Renamed files keep their 0600 mode. A missing
// intermediate file is normal; any other failure is reported, but the log is
// always reopened so that the logger stays usable.
func (l *Logger) rotate() error {
	err := l.f.Close()
	l.f = nil
	rot := func(i int) string { return fmt.Sprintf("%s.%d", fileName, i) }
	step := func(e error) {
		if e != nil && !errors.Is(e, fs.ErrNotExist) && err == nil {
			err = e
		}
	}
	step(l.root.Remove(rot(l.keep)))
	for i := l.keep - 1; i >= 1; i-- {
		step(l.root.Rename(rot(i), rot(i+1)))
	}
	step(l.root.Rename(fileName, rot(1)))
	if oerr := l.open(); oerr != nil {
		return errors.Join(err, oerr)
	}
	return err
}

// Close closes the log file. It is safe to call more than once.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var err error
	if l.f != nil {
		err = l.f.Close()
		l.f = nil
	}
	return errors.Join(err, l.root.Close())
}

type rotated struct {
	name string
	n    int
}

// rotatedNames lists writes.log.N files (N a canonical positive integer),
// ignoring anything else in the directory.
func rotatedNames(root *os.Root) ([]rotated, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var out []rotated
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), fileName+".")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(suffix)
		if err != nil || n < 1 || strconv.Itoa(n) != suffix {
			continue
		}
		out = append(out, rotated{e.Name(), n})
	}
	return out, nil
}

// ReadSince returns entries at or after since, oldest first, across the
// current and rotated files. Malformed and over-long lines are skipped.
// Timestamps have second precision, and since is compared at second precision, so same-second entries are included.
// A missing dir yields no entries. It takes no lock, so a concurrent rotation
// can make it miss or duplicate entries: it is a best-effort report view.
func ReadSince(dir string, since time.Time) ([]Entry, error) {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	names, err := rotatedNames(root)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(names, func(a, b rotated) int { return b.n - a.n }) // oldest (highest N) first
	paths := make([]string, 0, len(names)+1)
	for _, r := range names {
		paths = append(paths, r.name)
	}
	paths = append(paths, fileName)
	var out []Entry
	for _, p := range paths {
		es, err := readFile(root, p, since)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

func readFile(root *os.Root, name string, since time.Time) ([]Entry, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	since = since.Truncate(time.Second)
	var out []Entry
	r := bufio.NewReaderSize(f, 4096)
	for {
		line, ok, err := readLine(r)
		if err != nil {
			return out, err
		}
		if line == nil && !ok {
			return out, nil
		}
		parts := strings.Split(string(line), "\t")
		if len(parts) != 5 {
			continue
		}
		t, err := time.Parse(time.RFC3339, parts[0])
		if err != nil || t.Before(since) {
			continue
		}
		out = append(out, Entry{Time: t, Client: parts[1], Tool: parts[2], Path: parts[3], Result: parts[4]})
	}
}

// readLine returns the next line of at most maxLineBytes. A longer line is
// consumed and returned as an empty, non-nil slice (which fails parsing and
// is skipped), so memory stays bounded. At end of input it returns (nil,
// false, nil).
func readLine(r *bufio.Reader) (line []byte, ok bool, err error) {
	var buf []byte
	tooLong := false
	for {
		chunk, isPrefix, err := r.ReadLine()
		if errors.Is(err, io.EOF) {
			if buf == nil && !tooLong {
				return nil, false, nil
			}
			break
		}
		if err != nil {
			return nil, false, err
		}
		if !tooLong {
			if len(buf)+len(chunk) > maxLineBytes {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if !isPrefix {
			break
		}
	}
	if tooLong || buf == nil {
		return []byte{}, true, nil
	}
	return buf, true, nil
}
