//go:build linux || darwin

package vault

import "syscall"

// freeBytes returns the bytes available to unprivileged users on the
// filesystem holding dir (f_bavail, not f_bfree: root-reserved blocks are
// not usable by the server).
func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	// #nosec G115 -- the block size reported by statfs is always positive.
	return mulCap(st.Bavail, uint64(st.Bsize)), nil
}
