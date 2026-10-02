package vault

import "math"

// minFreeBytes is the free space a write needs on the vault's filesystem.
// The VPS is shared and small: a looping or hostile assistant must not fill
// the disk that other services (and the vault's own sync) depend on. The
// rate limit bounds requests, not bytes, so this floor is what caps growth.
// A write also needs room for its temp copy, so the floor sits far above any
// single note.
const minFreeBytes = 1 << 30

// checkDisk refuses a write when free space is below minFreeBytes. A
// filesystem that cannot report free space is not refused: the floor
// protects a shared disk, it is not an access control, and refusing every
// write on such a mount would make the vault read-only.
func (v *Vault) checkDisk() error {
	free, err := v.freeSpace()
	if err != nil {
		return nil
	}
	if free < minFreeBytes {
		return errf(CodeDiskLow, "the server's disk has less than %d MiB free: writes are paused until the owner frees space", minFreeBytes>>20)
	}
	return nil
}

// mulCap multiplies two block counts without wrapping.
func mulCap(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}
