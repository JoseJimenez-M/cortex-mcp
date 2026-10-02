//go:build windows

package fsperm

// On Windows, Go synthesizes mode bits (directories always report 0777) and
// chmod only toggles the read-only attribute. The bits cannot express
// multi-user access, so neither the shared-directory check nor the chmods
// mean anything here; access is governed by ACLs inherited from the parent.

// PrivateDir is a no-op on Windows.
func PrivateDir(string) error { return nil }

// PrivateFile is a no-op on Windows.
func PrivateFile(string) error { return nil }
