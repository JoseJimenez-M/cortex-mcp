package config_test

import (
	"testing"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
	"github.com/JoseJimenez-M/cortex-mcp/internal/vault"
)

// denyTable is run through config.Validate and vault.New. For character
// rules both must reject. configStricter marks entries the vault normalizes
// or skips but config rejects on purpose (see checkDeny).
var denyTable = []struct {
	name          string
	entry         string
	vaultRejects  bool
	configRejects bool
}{
	{"plain", "Private", false, false},
	{"nested", "Work/secret.md", false, false},
	{"dots in name", "a..b", false, false},
	{"control", "a\x00b", true, true},
	{"newline", "a\nb", true, true},
	{"bad utf8", "a\xffb", true, true},
	{"bidi override", "a\xe2\x80\xaeb", true, true},
	{"zero width", "a\xe2\x80\x8bb", true, true},
	{"bom", "\xef\xbb\xbfa", true, true},
	{"backslash", `a\b`, true, true},
	{"leading space", " a", true, true},
	{"trailing space", "a ", true, true},
	{"segment space", "a /b", true, true},
	{"segment trailing space", "a/b /c", true, true},
	// Config stricter than the vault.
	{"dotdot", "a/../b", false, true},
	{"absolute", "/etc", false, true},
	{"dot", ".", false, true},
	{"empty", "", false, true},
}

func TestDenyRulesAlignedWithVault(t *testing.T) {
	for _, tc := range denyTable {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c := config.Default()
			c.Vault, c.StateDir, c.PublicURL = dir, dir+"-state", "https://mcp.example.com"
			c.Deny = []string{tc.entry}
			cfgRejects := c.Validate() != nil
			v, err := vault.New(dir, vault.Options{Deny: []string{tc.entry}})
			if err == nil {
				_ = v.Close()
			}
			if cfgRejects != tc.configRejects || (err != nil) != tc.vaultRejects {
				t.Fatalf("config rejects=%v (want %v), vault rejects=%v (want %v)", cfgRejects, tc.configRejects, err != nil, tc.vaultRejects)
			}
			if tc.vaultRejects && !cfgRejects {
				t.Fatal("config accepts an entry the vault rejects")
			}
		})
	}
}
