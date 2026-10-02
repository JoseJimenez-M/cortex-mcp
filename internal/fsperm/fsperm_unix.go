//go:build !windows

package fsperm

import (
	"errors"
	"fmt"
	"os"
)

// PrivateDir restricts an existing directory to its owner (0700). It refuses
// a directory other users share (sticky bit or world-writable, like /tmp):
// chmod there would change it for everyone, and a private state dir must be
// dedicated.
func PrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if m := info.Mode(); m&os.ModeSticky != 0 || m.Perm()&0o002 != 0 {
		return fmt.Errorf("state dir %s is a shared directory; use a dedicated one", dir)
	}
	return os.Chmod(dir, 0o700) // #nosec G302 -- a directory needs the owner x bit; 0700 is the tightest usable mode
}

// PrivateFile restricts a file to its owner (0600). A missing file is not an
// error, so callers can pass optional side files such as SQLite -wal.
func PrivateFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
