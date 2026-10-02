package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
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

// read loads a path already validated by clean, frontmatter included.
func (v *Vault) read(p string) (*Note, error) {
	n, err := v.readContent(p)
	if err != nil {
		return nil, err
	}
	if fm, err := v.parseFM(n.Content); err != nil {
		// A broken frontmatter must not hide the note: the assistant may be
		// the one asked to repair it.
		n.FrontmatterError = err.Error()
	} else {
		n.Frontmatter = fm
	}
	return n, nil
}

// readContent is read without the frontmatter parse, for callers that only
// need the text (text search, backlinks, read-modify-write). Decoding YAML
// for every note of a scan would cost far more than the scan itself.
func (v *Vault) readContent(p string) (*Note, error) {
	if err := v.noSymlinks(p); err != nil {
		return nil, err
	}
	local := filepath.FromSlash(p)
	// Check before opening: opening a FIFO blocks until a writer appears.
	pre, err := v.root.Stat(local)
	if err != nil {
		return nil, fsErr(err, p)
	}
	if err := checkRegular(pre, p); err != nil {
		return nil, err
	}
	f, err := v.root.Open(local)
	if err != nil {
		return nil, fsErr(err, p)
	}
	defer func() { _ = f.Close() }()
	// Stat the open handle so size, mtime and content describe one file even
	// if the path is replaced meanwhile; this also re-checks the type.
	info, err := f.Stat()
	if err != nil {
		return nil, fsErr(err, p)
	}
	if err := checkRegular(info, p); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, v.maxRead+1))
	if err != nil {
		return nil, fsErr(err, p)
	}
	if int64(len(b)) > v.maxRead {
		return nil, errf(CodeNoteTooLarge, "%s is larger than %d bytes", p, v.maxRead)
	}
	return &Note{Path: p, Content: string(b), Version: version(b), Modified: info.ModTime().UTC()}, nil
}

// maxNoteBytes bounds the memory one Read can allocate. The server is
// internet-facing, so an oversized or hostile file must not exhaust RAM; the
// limit is far above any real note.
const maxNoteBytes = 8 << 20

func checkRegular(info os.FileInfo, p string) error {
	if info.IsDir() {
		return errf(CodeInvalidPath, "%s is a folder, not a note", p)
	}
	if !info.Mode().IsRegular() {
		return errf(CodeInvalidPath, "%s is not a regular file", p)
	}
	return nil
}
