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
	// MaxWriteBytes caps the input of one write; 0 means 1 MiB.
	MaxWriteBytes int64
}

// Vault is a Markdown folder opened with os.Root: every file operation is
// confined to the folder by the standard library, including symlinks that
// point outside it.
type Vault struct {
	root     *os.Root
	deny     []string
	maxWrite int64
	now      func() time.Time
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
	deny := make([]string, 0, len(opts.Deny))
	for _, d := range opts.Deny {
		d = strings.Trim(path.Clean("/"+filepath.ToSlash(d)), "/")
		if d == "" {
			continue
		}
		// Operator config error: an entry with characters clean rejects could
		// never match, which would silently leave the path unprotected.
		if err := checkChars(d); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("invalid deny entry %q: %w", d, err)
		}
		deny = append(deny, d)
	}
	return &Vault{root: r, deny: deny, maxWrite: maxWrite, now: time.Now}, nil
}

// Close releases the vault's directory handle.
func (v *Vault) Close() error { return v.root.Close() }
