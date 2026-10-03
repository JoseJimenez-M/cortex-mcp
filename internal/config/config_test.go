package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// abs builds an absolute path valid on the host OS.
func abs(parts ...string) string {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	return filepath.Join(append([]string{root}, parts...)...)
}

func valid() Config {
	c := Default()
	c.Vault, c.StateDir, c.PublicURL = abs("data", "vault"), abs("data", "state"), "https://mcp.example.com"
	return c
}

func yamlFor(c Config) string {
	return "vault: '" + c.Vault + "'\nstate_dir: '" + c.StateDir + "'\npublic_url: " + c.PublicURL + "\n"
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load(write(t, yamlFor(valid())))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || !c.BearerTokens || c.Limits.MaxWriteBytes != 1<<20 || c.Limits.RequestsPerMinute != 60 || c.Logs.MaxSizeMB != 5 || c.Logs.Keep != 3 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestLoadMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope.yaml")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "config "+p) {
		t.Fatalf("err = %v", err)
	}
	p = filepath.Join(t.TempDir(), "no-such-dir", "c.yaml")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "config "+p) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	_, err := Load(write(t, yamlFor(valid())+"bearer_token: true\n"))
	if err == nil || !strings.Contains(err.Error(), "bearer_token") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	_, err := Load(write(t, yamlFor(valid())+"---\n"+yamlFor(valid())))
	if err == nil || !strings.Contains(err.Error(), "config must contain a single YAML document") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsNonMapping(t *testing.T) {
	for _, body := range []string{"- a\n- b\n", "just a string\n", "42\n"} {
		_, err := Load(write(t, body))
		if err == nil || !strings.Contains(err.Error(), "must be a YAML mapping") {
			t.Errorf("%q: err = %v", body, err)
		}
	}
}

func TestLoadEmptyFileFailsValidation(t *testing.T) {
	_, err := Load(write(t, ""))
	if err == nil || !strings.Contains(err.Error(), "vault") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadDoesNotEchoValues(t *testing.T) {
	_, err := Load(write(t, yamlFor(valid())+"limits:\n  max_write_bytes: SECRETVALUE\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("error echoes file content: %v", err)
	}
}

func TestLoadPrefixesPath(t *testing.T) {
	p := write(t, "vault: relative\n")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateOK(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://mcp.example.com/", "https://mcp.example.com:8443",
		"http://127.0.0.2:8080", "http://localhost:443", "https://mcp.example.com:80", "https://xn--bcher-kva.example"} {
		c := valid()
		c.PublicURL = u
		if err := c.Validate(); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, l := range []string{":8080", "127.0.0.1:8765", "[::1]:9000", "localhost:1", "0.0.0.0:65535"} {
		c := valid()
		c.Listen = l
		if err := c.Validate(); err != nil {
			t.Errorf("listen %s rejected: %v", l, err)
		}
	}
	c := valid()
	c.Deny = []string{"Private", "Work/secret.md"}
	c.StateDir = abs("data", "vault2")
	c.Vault = abs("data", "vault")
	if err := c.Validate(); err != nil {
		t.Errorf("sibling with shared prefix rejected: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"vault relative":         {func(c *Config) { c.Vault = "relative" }, "vault:"},
		"vault empty":            {func(c *Config) { c.Vault = "" }, "vault:"},
		"state_dir empty":        {func(c *Config) { c.StateDir = "" }, "state_dir:"},
		"state_dir relative":     {func(c *Config) { c.StateDir = "s" }, "state_dir:"},
		"state_dir equal":        {func(c *Config) { c.StateDir = c.Vault }, "state_dir:"},
		"state_dir equal dirty":  {func(c *Config) { c.StateDir = c.Vault + string(filepath.Separator) + "." }, "state_dir:"},
		"state_dir inside":       {func(c *Config) { c.StateDir = filepath.Join(c.Vault, ".state") }, "state_dir:"},
		"state_dir deep inside":  {func(c *Config) { c.StateDir = filepath.Join(c.Vault, "a", "b") }, "state_dir:"},
		"url http":               {func(c *Config) { c.PublicURL = "http://mcp.example.com" }, "public_url:"},
		"url http lookalike":     {func(c *Config) { c.PublicURL = "http://localhost.example.com" }, "public_url:"},
		"url http ip lookalike":  {func(c *Config) { c.PublicURL = "http://127.0.0.1.nip.io" }, "public_url:"},
		"url http unspecified":   {func(c *Config) { c.PublicURL = "http://0.0.0.0:8080" }, "public_url:"},
		"url ftp":                {func(c *Config) { c.PublicURL = "ftp://mcp.example.com" }, "public_url:"},
		"url empty":              {func(c *Config) { c.PublicURL = "" }, "public_url:"},
		"url no host":            {func(c *Config) { c.PublicURL = "https://" }, "public_url:"},
		"url path":               {func(c *Config) { c.PublicURL = "https://mcp.example.com/mcp" }, "public_url:"},
		"url query":              {func(c *Config) { c.PublicURL = "https://mcp.example.com?a=b" }, "public_url:"},
		"url empty query":        {func(c *Config) { c.PublicURL = "https://mcp.example.com?" }, "public_url:"},
		"url fragment":           {func(c *Config) { c.PublicURL = "https://mcp.example.com#x" }, "public_url:"},
		"url userinfo":           {func(c *Config) { c.PublicURL = "https://user:pw@mcp.example.com" }, "public_url:"},
		"url user only":          {func(c *Config) { c.PublicURL = "https://user@mcp.example.com" }, "public_url:"},
		"url non-ASCII host":     {func(c *Config) { c.PublicURL = "https://bücher.example" }, "public_url:"},
		"url non-ASCII escaped":  {func(c *Config) { c.PublicURL = "https://b%C3%BCcher.example" }, "public_url:"},
		"listen empty":           {func(c *Config) { c.Listen = "" }, "listen:"},
		"listen port only":       {func(c *Config) { c.Listen = "8080" }, "listen:"},
		"listen host only":       {func(c *Config) { c.Listen = "localhost" }, "listen:"},
		"listen colon":           {func(c *Config) { c.Listen = ":" }, "listen:"},
		"listen port zero":       {func(c *Config) { c.Listen = ":0" }, "listen:"},
		"listen port big":        {func(c *Config) { c.Listen = ":65536" }, "listen:"},
		"listen named port":      {func(c *Config) { c.Listen = ":http" }, "listen:"},
		"instructions traversal": {func(c *Config) { c.InstructionsFile = "../x.md" }, "instructions_file:"},
		"instructions not md":    {func(c *Config) { c.InstructionsFile = "x.txt" }, "instructions_file:"},
		"instr control":          {func(c *Config) { c.InstructionsFile = "a\x01.md" }, "instructions_file:"},
		"instr format":           {func(c *Config) { c.InstructionsFile = "a\u200b.md" }, "instructions_file:"},
		"instr backslash":        {func(c *Config) { c.InstructionsFile = `a\b.md` }, "instructions_file:"},
		"instr bad utf8":         {func(c *Config) { c.InstructionsFile = "a\xff.md" }, "instructions_file:"},
		"instr seg space":        {func(c *Config) { c.InstructionsFile = "a /b.md" }, "instructions_file:"},
		"listen plus":            {func(c *Config) { c.Listen = ":+8080" }, "listen:"},
		"listen leading zero":    {func(c *Config) { c.Listen = ":08080" }, "listen:"},
		"url empty port":         {func(c *Config) { c.PublicURL = "https://mcp.example.com:" }, "public_url:"},
		"url plus port":          {func(c *Config) { c.PublicURL = "https://mcp.example.com:+443" }, "public_url:"},
		"url zero port":          {func(c *Config) { c.PublicURL = "https://mcp.example.com:0443" }, "public_url:"},
		// The issuer and resource are compared exactly, so public_url must
		// already be in the form a normalizing client would produce.
		"url upper host":         {func(c *Config) { c.PublicURL = "https://MCP.example.com" }, "public_url:"},
		"url upper localhost":    {func(c *Config) { c.PublicURL = "http://LOCALHOST:8080" }, "public_url:"},
		"url upper scheme":       {func(c *Config) { c.PublicURL = "HTTPS://mcp.example.com" }, "public_url:"},
		"url trailing dot":       {func(c *Config) { c.PublicURL = "https://mcp.example.com." }, "public_url:"},
		"url localhost dot":      {func(c *Config) { c.PublicURL = "http://localhost.:8080" }, "public_url:"},
		"url default https port": {func(c *Config) { c.PublicURL = "https://mcp.example.com:443" }, "public_url:"},
		"url default http port":  {func(c *Config) { c.PublicURL = "http://localhost:80" }, "public_url:"},
		"deny bad utf8":          {func(c *Config) { c.Deny = []string{"a\xffb"} }, "deny[0]"},
		"deny format char":       {func(c *Config) { c.Deny = []string{"a\u202eb"} }, "deny[0]"},
		"deny segment space":     {func(c *Config) { c.Deny = []string{"a /b"} }, "deny[0]"},
		"deny dot":               {func(c *Config) { c.Deny = []string{"."} }, "deny[0]"},
		"deny dot slash":         {func(c *Config) { c.Deny = []string{"./"} }, "deny[0]"},
		"deny slash":             {func(c *Config) { c.Deny = []string{"/"} }, "deny[0]"},
		"deny absolute":          {func(c *Config) { c.Deny = []string{abs("etc")} }, "deny[0]"},
		"deny dotdot":            {func(c *Config) { c.Deny = []string{"ok", "a/../b"} }, "deny[1]"},
		"deny backslash":         {func(c *Config) { c.Deny = []string{`a\b`} }, "deny[0]"},
		"deny control":           {func(c *Config) { c.Deny = []string{"a\x00b"} }, "deny[0]"},
		"deny newline":           {func(c *Config) { c.Deny = []string{"a\nb"} }, "deny[0]"},
		"deny leading space":     {func(c *Config) { c.Deny = []string{" a"} }, "deny[0]"},
		"deny trailing space":    {func(c *Config) { c.Deny = []string{"a "} }, "deny[0]"},
		"deny empty":             {func(c *Config) { c.Deny = []string{""} }, "deny[0]"},
		"bearer false":           {func(c *Config) { c.BearerTokens = false; c.OAuth.Enabled = false }, "bearer_tokens:"},
		"allowlist empty":        {func(c *Config) { c.OAuth.RedirectAllowlist = nil }, "oauth.redirect_allowlist:"},
		"allowlist bad":          {func(c *Config) { c.OAuth.RedirectAllowlist = []string{"loopback", "http://x/cb"} }, "oauth.redirect_allowlist[1]"},
		"allowlist too long":     {func(c *Config) { c.OAuth.RedirectAllowlist = slices.Repeat([]string{"loopback"}, 33) }, "oauth.redirect_allowlist:"},
		"write zero":             {func(c *Config) { c.Limits.MaxWriteBytes = 0 }, "limits.max_write_bytes:"},
		"write over 8MiB":        {func(c *Config) { c.Limits.MaxWriteBytes = 8<<20 + 1 }, "limits.max_write_bytes:"},
		"rpm zero":               {func(c *Config) { c.Limits.RequestsPerMinute = 0 }, "limits.requests_per_minute:"},
		"rpm over":               {func(c *Config) { c.Limits.RequestsPerMinute = 6001 }, "limits.requests_per_minute:"},
		"size zero":              {func(c *Config) { c.Logs.MaxSizeMB = 0 }, "logs.max_size_mb:"},
		"size over":              {func(c *Config) { c.Logs.MaxSizeMB = 1025 }, "logs.max_size_mb:"},
		"keep zero":              {func(c *Config) { c.Logs.Keep = 0 }, "logs.keep:"},
		"keep over":              {func(c *Config) { c.Logs.Keep = 101 }, "logs.keep:"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			tc.mutate(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateBoundsInclusive(t *testing.T) {
	c := valid()
	c.Limits = Limits{MaxWriteBytes: 8 << 20, RequestsPerMinute: 6000}
	c.Logs = Logs{MaxSizeMB: 1024, Keep: 100}
	if err := c.Validate(); err != nil {
		t.Fatalf("upper bounds rejected: %v", err)
	}
}

func TestValidateJoinsAllProblems(t *testing.T) {
	c := valid()
	c.Vault, c.Listen, c.Logs.Keep = "x", "", 0
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, k := range []string{"vault:", "listen:", "logs.keep:"} {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("missing %q in %v", k, err)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"localhost": true, "LocalHost": true, "localhost.": true, "127.0.0.1": true, "127.1.2.3": true,
		"::1": true, "": false, "0.0.0.0": false, "::": false, "example.com": false,
		"localhost.example.com": false, "10.0.0.1": false,
	} {
		if got := IsLoopbackHost(h); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestOAuthDefaults(t *testing.T) {
	c, err := Load(write(t, yamlFor(valid())))
	if err != nil {
		t.Fatal(err)
	}
	if !c.OAuth.Enabled || !slices.Equal(c.OAuth.RedirectAllowlist, DefaultRedirectAllowlist()) {
		t.Fatalf("oauth defaults = %+v", c.OAuth)
	}
	want := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector_platform_oauth_redirect",
		"https://chatgpt.com/connector/oauth/*",
		"https://agent.meta.ai/api/hatch/oauth/callback",
		"loopback",
	}
	if !slices.Equal(DefaultRedirectAllowlist(), want) {
		t.Fatalf("DefaultRedirectAllowlist = %v", DefaultRedirectAllowlist())
	}
}

// A list in the file replaces the defaults instead of appending to them.
func TestOAuthAllowlistReplacesDefaults(t *testing.T) {
	c, err := Load(write(t, yamlFor(valid())+"oauth:\n  redirect_allowlist:\n    - https://claude.ai/api/mcp/auth_callback\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.OAuth.RedirectAllowlist, []string{"https://claude.ai/api/mcp/auth_callback"}) || !c.OAuth.Enabled {
		t.Fatalf("oauth = %+v", c.OAuth)
	}
}

func TestCheckRedirectEntry(t *testing.T) {
	for _, ok := range []string{
		"loopback",
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/*",
		"https://example.com/cb",
		"https://example.com:8443/cb",
	} {
		if msg := CheckRedirectEntry(ok); msg != "" {
			t.Errorf("%q rejected: %s", ok, msg)
		}
	}
	for _, bad := range []string{
		"", "Loopback", "http://example.com/cb", "https://example.com", "https:///cb",
		"https://user@example.com/cb", "https://example.com/cb?x=1", "https://example.com/cb#f",
		"https://example.com/a/../cb", "https://example.com/./cb", `https://example.com\cb`,
		"https://example.com/*/cb", "https://example.com/cb*", "https://*.example.com/cb",
		"https://example.com/c b", "https://exämple.com/cb", "javascript:alert(1)//x",
		"https://example.com/" + strings.Repeat("a", 600),
		"https://:443/cb", "https://x:0/cb", "https://x:/cb", "https://x:65536/cb", "https://x:+80/cb",
		"https://Example.com/cb", "https://example.com./cb", "https://example.com/%2e%2e/cb",
		"https://example.com/a%2fb", "https://exa,mple.com/cb", "https://.example.com/cb",
		"https://a..b/cb", "https://-a.com/cb", "https://[::1]/cb", "https://exa_mple.com/cb",
		"https://127.0.0.1/cb", "https://1.2.3.4/cb", "https://2130706433/cb", "https://0x7f000001/cb",
		"https://example.0x7f/cb", "https://localhost/cb", "https://x:080/cb", "https://x:00443/cb",
	} {
		if CheckRedirectEntry(bad) == "" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBearerFalseNeedsOAuth(t *testing.T) {
	c := valid()
	c.BearerTokens = false
	if err := c.Validate(); err != nil {
		t.Fatalf("bearer_tokens false with OAuth enabled rejected: %v", err)
	}
	c.OAuth.Enabled = false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "bearer_tokens: false requires oauth.enabled") {
		t.Fatalf("err = %v", err)
	}
}

func TestTrustedProxiesDefaultEmptyAndLoad(t *testing.T) {
	if len(Default().TrustedProxies) != 0 {
		t.Fatalf("default trusted_proxies = %v", Default().TrustedProxies)
	}
	c, err := Load(write(t, yamlFor(valid())+"trusted_proxies:\n  - 172.18.0.0/16\n  - fd00::/64\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.TrustedProxies, []string{"172.18.0.0/16", "fd00::/64"}) {
		t.Fatalf("trusted_proxies = %v", c.TrustedProxies)
	}
}

func TestCheckTrustedProxy(t *testing.T) {
	for _, ok := range []string{"172.18.0.0/16", "127.0.0.1/32", "10.0.0.0/8", "fd00::/32", "fd00:1:2:3::/64", "::1/128"} {
		if msg := CheckTrustedProxy(ok); msg != "" {
			t.Errorf("%q rejected: %s", ok, msg)
		}
	}
	// Shorter than /8 (IPv4) or /32 (IPv6) trusts a large part of the
	// internet to write X-Forwarded-For, a typo rather than a proxy network.
	for _, bad := range []string{"", "nope", "172.18.0.2", "172.18.0.1/16", "0.0.0.0/0", "::/0", "::ffff:10.0.0.0/104", "10.0.0.0/33", " 10.0.0.0/8", "fe80::%eth0/64",
		"8.0.0.0/7", "0.0.0.0/1", "fd00::/8", "2000::/3", "2001:db8::/31"} {
		if msg := CheckTrustedProxy(bad); msg == "" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	c := valid()
	c.TrustedProxies = []string{"10.0.0.0/8", "172.18.0.1/16"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxies[1]") {
		t.Fatalf("err = %v", err)
	}
	c.TrustedProxies = slices.Repeat([]string{"10.0.0.0/8"}, 33)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxies:") {
		t.Fatalf("err = %v", err)
	}
}
