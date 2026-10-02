package vault

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Options configure a Vault.
type Options struct {
	// Deny lists extra vault-relative files or folders that are never accessible.
	Deny []string
	// ReadOnly lists vault-relative notes that tools may read but never
	// write, delete, or move: the server instructions file, so an assistant
	// cannot rewrite the rules every other assistant receives.
	ReadOnly []string
	// MaxWriteBytes caps the input of one write; 0 means 1 MiB.
	MaxWriteBytes int64
}

// Vault is a Markdown folder opened with os.Root: every file operation is
// confined to the folder by the standard library, including symlinks that
// point outside it.
type Vault struct {
	root     *os.Root
	deny     []string
	readOnly []string
	maxWrite int64
	maxRead  int64
	now      func() time.Time
	locks    lockMap
	// link is the hard-link primitive; a field so tests can simulate
	// filesystems without hard links.
	link func(oldname, newname string) error
	// remove drops the source name after a move's link; a field so tests
	// can simulate a failure or an external process racing the move.
	remove func(name string) error
	// backlinks is the post-move scan; a field so tests can inject a failure.
	backlinks func(rel string) ([]string, error)
	// parseFM parses a note's frontmatter on read; a field so tests can
	// prove that scans which do not need it never call it.
	parseFM func(content string) (map[string]any, error)
	// freeSpace reports the bytes available on the vault's filesystem; a
	// field so tests can simulate a full disk.
	freeSpace func() (uint64, error)
}

// New opens dir as a vault. dir must exist.
func New(dir string, opts Options) (*Vault, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	maxWrite := opts.MaxWriteBytes
	if maxWrite <= 0 {
		maxWrite = 1 << 20
	}
	deny, err := normalizeEntries(opts.Deny)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("invalid deny entry %w", err)
	}
	readOnly, err := normalizeEntries(opts.ReadOnly)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("invalid read-only entry %w", err)
	}
	v := &Vault{root: r, deny: deny, readOnly: readOnly, maxWrite: maxWrite, maxRead: maxNoteBytes, now: time.Now}
	v.link = r.Link
	v.remove = r.Remove
	v.backlinks = v.Backlinks
	v.parseFM = parseFrontmatter
	v.freeSpace = func() (uint64, error) { return freeBytes(dir) }
	return v, nil
}

// normalizeEntries cleans operator-supplied vault-relative paths to the
// canonical slash form clean produces, dropping entries that clean to the
// root.
func normalizeEntries(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.Trim(path.Clean("/"+filepath.ToSlash(d)), "/")
		if d == "" {
			continue
		}
		// Operator config error: an entry with characters clean rejects could
		// never match, which would silently leave the path unprotected.
		if err := checkChars(d); err != nil {
			return nil, fmt.Errorf("%q: %w", d, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// Close releases the vault's directory handle.
func (v *Vault) Close() error { return v.root.Close() }
