package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// maxTrashAttempts bounds the clash-suffix search in Delete.
const maxTrashAttempts = 1000

// rename moves the note src to dst without ever replacing an existing dst.
// Callers hold the locks for both paths and have run noSymlinks on both.
//
// The vault lock does not cover external processes (Obsidian, sync tools),
// and rename(2) silently replaces a file created after an existence check.
// So the preferred publish is link(2) of src to dst, which is atomic and fails
// with EEXIST, followed by removing src. Content, mode and mtime are those of
// the original file because nothing is rewritten. A crash between the link and
// the remove leaves the note under both names: duplicated, never lost.
//
// Filesystems without hard links (FAT, some FUSE and network mounts) fall
// back to Lstat then rename. A target created in the few microseconds between
// the two can then be overwritten: a known residual race, accepted because
// only an external writer can trigger it on such a filesystem.
func (v *Vault) rename(src, dst string) error {
	info, err := v.root.Lstat(filepath.FromSlash(src))
	if err != nil {
		return fsErr(err, src)
	}
	if info.IsDir() {
		return errf(CodeInvalidPath, "%s is a folder, not a note", src)
	}
	if err := v.absent(dst); err != nil {
		return err
	}
	if dir := path.Dir(dst); dir != "." {
		if err := v.root.MkdirAll(filepath.FromSlash(dir), 0o755); err != nil {
			return fsErr(err, dir)
		}
	}
	lsrc, ldst := filepath.FromSlash(src), filepath.FromSlash(dst)
	lerr := v.link(lsrc, ldst)
	switch {
	case lerr == nil:
		if err := v.root.Remove(lsrc); err != nil {
			// The note now exists under both names; surface the failure
			// rather than pretend the move completed.
			return fsErr(err, src)
		}
	case linkUnsupported(lerr):
		if err := v.absent(dst); err != nil {
			return err
		}
		if err := v.root.Rename(lsrc, ldst); err != nil {
			return fsErr(err, src)
		}
	default:
		return fsErr(lerr, dst)
	}
	v.syncDir(dst)
	v.syncDir(src)
	return nil
}

// absent returns CodeExists when anything (even a dangling symlink) is at p.
func (v *Vault) absent(p string) error {
	_, err := v.root.Lstat(filepath.FromSlash(p))
	switch {
	case err == nil:
		return errf(CodeExists, "%s already exists", p)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fsErr(err, p)
	}
}

// Move renames a note and returns the notes that still link to the old
// path. Links are reported, never rewritten: rewriting other notes is a
// larger, riskier edit than the one requested.
func (v *Vault) Move(from, to string) ([]string, error) {
	src, err := v.clean(from, accessMoveFrom, true)
	if err != nil {
		return nil, err
	}
	dst, err := v.clean(to, accessWrite, true)
	if err != nil {
		return nil, err
	}
	if src == dst {
		return nil, errf(CodeInvalidInput, "source and target are the same")
	}
	if err := v.noSymlinks(src); err != nil {
		return nil, err
	}
	if err := v.noSymlinks(dst); err != nil {
		return nil, err
	}
	unlock := v.locks.lock(src, dst)
	err = v.rename(src, dst)
	unlock()
	if err != nil {
		return nil, err
	}
	return v.Backlinks(src)
}

// Delete moves a note into .trash/, keeping its folder path so a restore
// is obvious. A name clash in the trash gets a timestamp suffix, and a
// counter when that name is taken too (two deletes in the same second). No
// bytes are ever removed.
func (v *Vault) Delete(rel string) (string, error) {
	p, err := v.clean(rel, accessWrite, true)
	if err != nil {
		return "", err
	}
	base := path.Join(trashDir, p)
	if err := v.noSymlinks(p); err != nil {
		return "", err
	}
	// .trash and its subfolders must be real folders: a link there would
	// redirect the note out of the vault's protected layout.
	if err := v.noSymlinks(path.Dir(base)); err != nil {
		return "", err
	}
	defer v.locks.lock(p, base)()
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext) + "." + v.now().UTC().Format("20060102T150405")
	dst := base
	for i := 1; i <= maxTrashAttempts; i++ {
		err := v.rename(p, dst)
		if err == nil {
			return dst, nil
		}
		// Only a taken trash name is retried; the source was checked first
		// by rename, so a missing note still reports not found.
		if CodeOf(err) != CodeExists {
			return "", err
		}
		dst = stem + ext
		if i > 1 {
			dst = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
	}
	return "", errf(CodeExists, "no free name in .trash for %s", p)
}
