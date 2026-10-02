package vault

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
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
	// A rewrite must not silently change the note's permissions (a 0600
	// private note must not become 0644); new notes get 0644 filtered by the
	// umask, like any file the operator creates. Lstat, so a symlink is "not
	// regular" and gets the default. Rename-based writes make the server's
	// user the owner of the rewritten file: documented, not fixed.
	mode, preserve := fs.FileMode(0o644), false
	if info, err := v.root.Lstat(filepath.FromSlash(p)); err == nil && info.Mode().IsRegular() {
		mode, preserve = info.Mode().Perm(), true
	}
	if err := v.writeFileExcl(tmp, data, mode, preserve); err != nil {
		return "", fsErr(err, p)
	}
	return tmp, nil
}

// writeFileExcl creates name (it must not exist), writes data, fsyncs and
// closes. On any failure after the create it removes only the file it made.
// With preserve, mode is copied from an existing note via chmod so the umask
// cannot alter it; otherwise mode goes to OpenFile and the umask applies.
func (v *Vault) writeFileExcl(name string, data []byte, mode fs.FileMode, preserve bool) error {
	local := filepath.FromSlash(name)
	f, err := v.root.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if preserve {
		// Best effort: some FUSE and FAT mounts reject setattr, and keeping
		// the mode is a nicety, not a guarantee worth failing a write for.
		_ = f.Chmod(mode)
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = v.root.Remove(local)
	}
	return werr
}

// linkUnsupported reports whether err means the filesystem cannot make this
// hard link (as opposed to a real failure such as EEXIST or EIO).
func linkUnsupported(err error) bool {
	// ErrUnsupported covers ENOSYS/ENOTSUP/EOPNOTSUPP on unix and
	// ERROR_NOT_SUPPORTED/CALL_NOT_IMPLEMENTED on Windows.
	return errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EXDEV) ||
		errors.Is(err, syscall.EMLINK)
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
// one, never a partial file, and sync tools never see half a note. Parent
// folders created by MkdirAll are not fsynced: durability is best effort by
// design.
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

// writeNew publishes data at p only if p does not exist. rename would
// silently replace a file that an external process (Obsidian, a sync tool)
// created after Create's existence check, and the vault lock does not cover
// those processes. The preferred path is link(2) of a fully written temp
// file: atomic, fails with EEXIST, and readers never see a partial note.
// Filesystems without hard links (FAT, some FUSE and network mounts) fall
// back to creating the target with O_EXCL and writing in place: it still
// never clobbers, but a sync tool may briefly see a partial NEW note, and a
// crash mid-write can leave a truncated new note (nothing existing is lost).
func (v *Vault) writeNew(p string, data []byte) error {
	tmp, err := v.stage(p, data)
	if err != nil {
		return err
	}
	lerr := v.link(filepath.FromSlash(tmp), filepath.FromSlash(p))
	// The temp name is dropped on every path; after a successful link the
	// note is already complete under its real name.
	_ = v.root.Remove(filepath.FromSlash(tmp))
	switch {
	case lerr == nil:
	case linkUnsupported(lerr):
		if err := v.writeFileExcl(p, data, 0o644, false); err != nil {
			return fsErr(err, p)
		}
	default:
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
	// Keep the invariant explicit: a note we write must stay readable.
	if int64(len(content)) > v.maxRead {
		return "", errf(CodeTooLarge, "%s would be larger than %d bytes", p, v.maxRead)
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
	// Repeated appends must never grow a note past what read accepts.
	if int64(len(out)) > v.maxRead {
		return "", errf(CodeTooLarge, "%s would grow past %d bytes", p, v.maxRead)
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
