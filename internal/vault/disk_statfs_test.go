//go:build linux || darwin

package vault

import "testing"

func TestFreeSpaceReportsTheVaultFilesystem(t *testing.T) {
	v, _ := newTestVault(t, Options{})
	free, err := v.freeSpace()
	if err != nil || free == 0 {
		t.Fatalf("freeSpace = %d, %v", free, err)
	}
}
