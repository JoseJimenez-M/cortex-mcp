package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"time"
)

// Note is a note as returned to assistants.
type Note struct {
	Path             string
	Content          string
	Frontmatter      map[string]any // nil when the note has none or it is invalid
	FrontmatterError string         // set when the frontmatter cannot be parsed
	Version          string
	Modified         time.Time
}

// version is a short content hash used for optimistic concurrency: a
// guarded write must present the version it read.
func version(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:8])
}

// Read returns one note.
func (v *Vault) Read(rel string) (*Note, error) {
	p, err := v.clean(rel, accessRead, true)
	if err != nil {
		return nil, err
	}
	return v.read(p)
}

// read loads a path already validated by clean.
func (v *Vault) read(p string) (*Note, error) {
	info, err := v.root.Stat(filepath.FromSlash(p))
	if err != nil {
		return nil, fsErr(err, p)
	}
	if info.IsDir() {
		return nil, errf(CodeInvalidPath, "%s is a folder, not a note", p)
	}
	b, err := v.root.ReadFile(filepath.FromSlash(p))
	if err != nil {
		return nil, fsErr(err, p)
	}
	n := &Note{Path: p, Content: string(b), Version: version(b), Modified: info.ModTime().UTC()}
	if fm, err := parseFrontmatter(n.Content); err != nil {
		// A broken frontmatter must not hide the note: the assistant may be
		// the one asked to repair it.
		n.FrontmatterError = err.Error()
	} else {
		n.Frontmatter = fm
	}
	return n, nil
}
