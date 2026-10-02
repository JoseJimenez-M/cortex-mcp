//go:build unix

package vault

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadRejectsFIFOWithoutBlocking(t *testing.T) {
	v, dir := newTestVault(t, Options{})
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.md"), 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	_, err := v.Read("pipe.md")
	wantCode(t, err, CodeInvalidPath)
}
