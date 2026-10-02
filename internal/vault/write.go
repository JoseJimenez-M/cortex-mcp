package vault

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// stage writes data to a fresh temp file next to p, fsynced and closed, and
// returns its vault-relative path. The caller must rename or remove it. Temp
// names start with a dot, which Obsidian ignores.
func (v *Vault) stage(p string, data []byte) (string, error) {
	dir := path.Dir(p)
	if dir != "." {
		if err := v.root.MkdirAll(filepath.FromSlash(dir), 0o755); err != nil {
			return "", fsErr(err, dir)
		}
	}
	tmp := path.Join(dir, ".cortex-tmp-"+rand.Text())
	f, err := v.root.OpenFile(filepath.FromSlash(tmp), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", fsErr(err, p)
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = v.root.Remove(filepath.FromSlash(tmp))
		return "", fsErr(werr, p)
	}
	return tmp, nil
}

// syncDir flushes the folder entry so the rename or link survives a power
// loss. It is best effort: the note is already visible, and not every
// filesystem supports fsync on a folder.
func (v *Vault) syncDir(p string) {
	d, err := v.root.Open(filepath.FromSlash(path.Dir(p)))
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// writeAtomic replaces p with data: write a temp file in the same folder,
// fsync, rename over the target. A crash leaves the old note or the new
// one, never a partial file, and sync tools never see half a note.
func (v *Vault) writeAtomic(p string, data []byte) error {
	tmp, err := v.stage(p, data)
	if err != nil {
		return err
	}
	if err := v.root.Rename(filepath.FromSlash(tmp), filepath.FromSlash(p)); err != nil {
		_ = v.root.Remove(filepath.FromSlash(tmp))
		return fsErr(err, p)
	}
	v.syncDir(p)
	return nil
}

// writeNew atomically publishes data at p only if p does not exist. rename
// would silently replace a file that an external process (Obsidian, a sync
// tool) created after Create's existence check, and the vault lock does not
// cover those processes. link(2) fails with EEXIST instead, atomically, and
// the temp name is then dropped. Trade-off: this needs hard-link support on
// the vault's filesystem (ext4, xfs, btrfs, APFS, NTFS have it; FAT does
// not), and a failure there is reported rather than falling back to an
// overwrite-capable rename.
func (v *Vault) writeNew(p string, data []byte) error {
	tmp, err := v.stage(p, data)
	if err != nil {
		return err
	}
	lerr := v.root.Link(filepath.FromSlash(tmp), filepath.FromSlash(p))
	// The temp name is dropped on both paths; after a successful link the
	// note is already complete under its real name.
	_ = v.root.Remove(filepath.FromSlash(tmp))
	if lerr != nil {
		return fsErr(lerr, p)
	}
	v.syncDir(p)
	return nil
}

func (v *Vault) checkSize(n int) error {
	if int64(n) > v.maxWrite {
		return errf(CodeTooLarge, "write is %d bytes, the limit is %d", n, v.maxWrite)
	}
	return nil
}

// Create writes a new note and fails if it already exists.
func (v *Vault) Create(rel, content string) (string, error) {
	p, err := v.clean(rel, accessWrite, true)
	if err != nil {
		return "", err
	}
	if err := v.checkSize(len(content)); err != nil {
		return "", err
	}
	defer v.locks.lock(p)()
	if _, err := v.root.Lstat(filepath.FromSlash(p)); err == nil {
		return "", errf(CodeExists, "%s already exists: use append or replace_section", p)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fsErr(err, p)
	}
	data := []byte(content)
	if err := v.writeNew(p, data); err != nil {
		return "", err
	}
	return version(data), nil
}

// modify runs fn on the current content of an existing note, under that
// note's lock, and writes the result. When guarded, ver must equal the
// note's current version, so a stale edit can never overwrite a newer one.
func (v *Vault) modify(rel, ver string, guarded bool, fn func(string) (string, error)) (string, error) {
	p, err := v.clean(rel, accessWrite, true)
	if err != nil {
		return "", err
	}
	if guarded && ver == "" {
		return "", errf(CodeVersionRequired, "pass the version from your last read_note")
	}
	defer v.locks.lock(p)()
	n, err := v.read(p)
	if err != nil {
		return "", err
	}
	if guarded && n.Version != ver {
		return "", errf(CodeChanged, "%s was modified since you read it: call read_note again", p)
	}
	out, err := fn(n.Content)
	if err != nil {
		return "", err
	}
	data := []byte(out)
	if err := v.writeAtomic(p, data); err != nil {
		return "", err
	}
	return version(data), nil
}

// Append adds text at the end of an existing note. It needs no version:
// appending cannot overwrite anyone's edit.
func (v *Vault) Append(rel, text string) (string, error) {
	if strings.TrimSpace(text) == "" {
		return "", errf(CodeInvalidInput, "nothing to append")
	}
	if err := v.checkSize(len(text)); err != nil {
		return "", err
	}
	return v.modify(rel, "", false, func(c string) (string, error) { return appendToEnd(c, text), nil })
}

// appendToEnd puts text on its own line(s) at the end and leaves exactly
// one trailing newline.
func appendToEnd(content, text string) string {
	text = strings.TrimRight(text, "\n") + "\n"
	if content == "" {
		return text
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + text
}
