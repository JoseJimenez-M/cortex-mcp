//go:build !(linux || darwin)

package vault

import "errors"

// freeBytes is not implemented here: syscall.Statfs is missing or has
// different field types on other platforms (Windows, the BSDs). The disk
// floor then does not apply; Linux is the supported target.
func freeBytes(string) (uint64, error) { return 0, errors.ErrUnsupported }
