// Package config loads and validates the single cortex-mcp config file.
//
// It is a leaf package: it imports nothing from this module, so rules that
// the vault also enforces (for example deny entries) are re-checked here in
// plain form to fail at startup with a config-level message.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Upper bounds. MaxWriteBytes matches the vault's per-note read cap (8 MiB):
// a larger write could never be read back.
const (
	maxWriteBytesCap = 8 << 20
	maxRPMCap        = 6000
	maxLogSizeMBCap  = 1024
	maxLogKeepCap    = 100
	maxConfigBytes   = 1 << 20

	maxRedirectEntries    = 32
	maxRedirectEntryBytes = 512
)

// Limits are the per-request and per-client ceilings.
type Limits struct {
	MaxWriteBytes     int64 `yaml:"max_write_bytes"`
	RequestsPerMinute int   `yaml:"requests_per_minute"`
}

// Logs controls write-log rotation.
type Logs struct {
	MaxSizeMB int `yaml:"max_size_mb"`
	Keep      int `yaml:"keep"`
}

// OAuth configures the built-in OAuth 2.1 authorization server (spec 6.2).
// Enabled defaults to true: login refuses until the owner runs
// "cortex-mcp setup", which is the only step that creates secrets, so an
// unconfigured server exposes nothing usable. false removes every OAuth
// route and the resource_metadata link.
type OAuth struct {
	Enabled           bool     `yaml:"enabled"`
	RedirectAllowlist []string `yaml:"redirect_allowlist"`
}

// DefaultRedirectAllowlist is the redirect allowlist from spec 6.2: the
// published callbacks of claude.ai, ChatGPT, and Meta Muse, plus loopback
// for native clients such as Claude Code. A fresh slice each call, so no
// caller can change the defaults for another.
func DefaultRedirectAllowlist() []string {
	return []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector_platform_oauth_redirect",
		"https://chatgpt.com/connector/oauth/*",
		"https://agent.meta.ai/api/hatch/oauth/callback",
		"loopback",
	}
}

// Config is the whole server configuration. No field is secret: secrets
// live only in the auth state under StateDir.
type Config struct {
	Vault            string   `yaml:"vault"`
	StateDir         string   `yaml:"state_dir"`
	PublicURL        string   `yaml:"public_url"`
	Listen           string   `yaml:"listen"`
	InstructionsFile string   `yaml:"instructions_file"`
	Deny             []string `yaml:"deny"`
	BearerTokens     bool     `yaml:"bearer_tokens"`
	OAuth            OAuth    `yaml:"oauth"`
	Limits           Limits   `yaml:"limits"`
	Logs             Logs     `yaml:"logs"`
}

// Default returns the defaults; Load decodes the file on top of them, so a
// key missing from the file keeps its default.
func Default() Config {
	return Config{
		// Loopback by default: the server speaks plain HTTP and belongs
		// behind a TLS proxy on the same host. Containers need ":8080" so the
		// port is reachable from outside the container's network namespace.
		Listen:       "127.0.0.1:8080",
		BearerTokens: true,
		OAuth:        OAuth{Enabled: true, RedirectAllowlist: DefaultRedirectAllowlist()},
		Limits:       Limits{MaxWriteBytes: 1 << 20, RequestsPerMinute: 60},
		Logs:         Logs{MaxSizeMB: 5, Keep: 3},
	}
}

// Load reads, decodes, and validates a config file. The path comes from the
// operator's command line. It is opened through os.OpenRoot on its directory
// so the file read is not an arbitrary-path open.
func Load(path string) (Config, error) {
	raw, err := readFile(path)
	if err != nil {
		return Config{}, err
	}
	c, err := decode(raw)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func readFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	defer root.Close()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("config %s: larger than %d bytes", path, maxConfigBytes)
	}
	return raw, nil
}

// valueInBackticks matches the quoted scalar yaml.v3 puts in type errors
// ("cannot unmarshal !!str `abc` into int"); values are redacted so a
// mistyped secret never reaches logs.
var valueInBackticks = regexp.MustCompile("`[^`]*`")

func decode(raw []byte) (Config, error) {
	// First pass into a Node only to check shape: one document, a mapping.
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	err := dec.Decode(&node)
	c := Default()
	if errors.Is(err, io.EOF) {
		return c, nil // empty file: defaults, Validate reports what is missing
	}
	if err != nil {
		return Config{}, redact(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config must contain a single YAML document")
	}
	if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
		return Config{}, errors.New("top level must be a YAML mapping of keys to values")
	}
	// Second pass with strict keys into the typed struct.
	strict := yaml.NewDecoder(bytes.NewReader(raw))
	strict.KnownFields(true)
	if err := strict.Decode(&c); err != nil {
		return Config{}, redact(err)
	}
	return c, nil
}

func redact(err error) error {
	return errors.New(valueInBackticks.ReplaceAllString(err.Error(), "<value>"))
}

// IsLoopbackHost reports whether h (a URL or listen host, without port or
// brackets) is localhost (any case, with or without a trailing dot) or a
// loopback IP (127.0.0.0/8, ::1). It is the single definition: config uses
// it to allow plain http, the server to decide on DNS-rebinding protection,
// and serve to warn about a listener reachable from the network, so the
// three can never disagree about what "local" means.
func IsLoopbackHost(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Validate reports every problem at once. Paths are compared lexically
// (filepath.Clean); symlinks are not resolved here, operators own their paths.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !filepath.IsAbs(c.Vault) {
		add("vault: must be an absolute path")
	}
	if !filepath.IsAbs(c.StateDir) {
		add("state_dir: must be an absolute path")
	} else if filepath.IsAbs(c.Vault) && within(c.Vault, c.StateDir) {
		// Deliberate tightening of the spec ("outside by default"): auth
		// secrets must never sync along with the notes.
		add("state_dir: must not be the vault or inside it")
	}
	if msg := checkPublicURL(c.PublicURL); msg != "" {
		add("public_url: %s", msg)
	}
	if msg := checkListen(c.Listen); msg != "" {
		add("listen: %s", msg)
	}
	if c.InstructionsFile != "" {
		if !filepath.IsLocal(c.InstructionsFile) || !strings.EqualFold(filepath.Ext(c.InstructionsFile), ".md") {
			add("instructions_file: must be a .md file inside the vault")
		} else if msg := checkChars(c.InstructionsFile); msg != "" {
			add("instructions_file: %s", msg)
		}
	}
	for i, d := range c.Deny {
		if msg := checkDeny(d); msg != "" {
			add("deny[%d] (%q): %s", i, d, msg)
		}
	}
	if !c.BearerTokens && !c.OAuth.Enabled {
		add("bearer_tokens: false requires oauth.enabled: true, or no client could authenticate")
	}
	if c.OAuth.Enabled && len(c.OAuth.RedirectAllowlist) == 0 {
		add("oauth.redirect_allowlist: must not be empty while oauth.enabled is true")
	}
	if len(c.OAuth.RedirectAllowlist) > maxRedirectEntries {
		add("oauth.redirect_allowlist: at most %d entries", maxRedirectEntries)
	}
	for i, e := range c.OAuth.RedirectAllowlist {
		if msg := CheckRedirectEntry(e); msg != "" {
			add("oauth.redirect_allowlist[%d] (%q): %s", i, e, msg)
		}
	}
	if c.Limits.MaxWriteBytes <= 0 || c.Limits.MaxWriteBytes > maxWriteBytesCap {
		add("limits.max_write_bytes: must be between 1 and %d (the vault cannot read back a larger note)", maxWriteBytesCap)
	}
	if c.Limits.RequestsPerMinute <= 0 || c.Limits.RequestsPerMinute > maxRPMCap {
		add("limits.requests_per_minute: must be between 1 and %d", maxRPMCap)
	}
	if c.Logs.MaxSizeMB <= 0 || c.Logs.MaxSizeMB > maxLogSizeMBCap {
		add("logs.max_size_mb: must be between 1 and %d", maxLogSizeMBCap)
	}
	if c.Logs.Keep < 1 || c.Logs.Keep > maxLogKeepCap {
		add("logs.keep: must be between 1 and %d", maxLogKeepCap)
	}
	return errors.Join(errs...)
}

// within reports whether child equals parent or lies beneath it. It goes
// through filepath.Rel so /data/vault2 is not "inside" /data/vault.
func within(parent, child string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func checkPublicURL(raw string) string {
	const hint = "must be an https URL with only a host (http is allowed only for localhost and loopback IPs)"
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return hint
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && IsLoopbackHost(u.Hostname())) {
		return hint
	}
	// The issuer and the MCP resource URL are derived from this string and
	// compared byte for byte, so it must already be in the form clients
	// normalize URLs to: lowercase scheme and host, no trailing dot, no
	// default port.
	if !strings.HasPrefix(raw, u.Scheme+"://") || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") {
		return "must be written in canonical form: lowercase scheme and host, no trailing dot"
	}
	if p := u.Port(); (u.Scheme == "https" && p == "443") || (u.Scheme == "http" && p == "80") {
		return "must not name the default port of its scheme"
	}
	if strings.HasSuffix(u.Host, ":") {
		return "has an empty port after the colon"
	}
	if p := u.Port(); p != "" && !validPort(p) {
		return "port must be a plain number from 1 to 65535"
	}
	if u.User != nil {
		return "must not contain credentials (they would end up in logs)"
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return "must not contain a path, query, or fragment"
	}
	return ""
}

func checkListen(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "must be host:port such as :8080"
	}
	if !validPort(port) {
		return "port must be a plain number from 1 to 65535"
	}
	return ""
}

// validPort accepts only digits without a sign or leading zeros, so the
// value read is the value bound.
func validPort(p string) bool {
	if p == "" || p[0] == '0' {
		return false
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(p)
	return err == nil && n <= 65535
}

// checkChars mirrors vault.checkChars (internal/vault/path.go); config is a
// leaf and cannot import it. config_vault_test.go runs a shared table through
// both so they cannot drift. Keep the two in sync.
func checkChars(s string) string {
	if !utf8.ValidString(s) {
		return "must be valid UTF-8"
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "must not contain control or format characters"
		}
		if r == '\\' {
			return "must not contain a backslash"
		}
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			continue
		}
		first, _ := utf8.DecodeRuneInString(seg)
		last, _ := utf8.DecodeLastRuneInString(seg)
		if unicode.IsSpace(first) || unicode.IsSpace(last) {
			return "path segments must not start or end with whitespace"
		}
	}
	return ""
}

// checkDeny is stricter than vault.New on purpose: the vault normalizes
// "a/../b" to "b" and skips entries that clean to nothing, which would
// silently protect a different path than the operator wrote.
func checkDeny(d string) string {
	if d == "" {
		return "must not be empty"
	}
	if msg := checkChars(d); msg != "" {
		return msg
	}
	if filepath.IsAbs(d) || strings.HasPrefix(d, "/") {
		return "must be relative to the vault"
	}
	for _, seg := range strings.Split(d, "/") {
		if seg == ".." {
			return `must not contain ".."`
		}
	}
	if path.Clean(d) == "." {
		return "refers to the vault root and would match nothing"
	}
	return ""
}

// CheckRedirectEntry validates one redirect allowlist entry and returns ""
// when it is valid. It is the single definition of the syntax: the OAuth
// package calls it when it builds its matcher, so the two cannot disagree.
// Entries are "loopback" or an https URL with a host and a path; a final "*"
// right after a "/" makes the entry a prefix for exactly one more path
// segment (see internal/oauth/redirect.go).
func CheckRedirectEntry(e string) string {
	if e == "loopback" {
		return ""
	}
	if len(e) > maxRedirectEntryBytes {
		return fmt.Sprintf("longer than %d bytes", maxRedirectEntryBytes)
	}
	for _, r := range e {
		if r <= ' ' || r >= 0x7f {
			return "must be printable ASCII without spaces"
		}
	}
	body := e
	if strings.HasSuffix(e, "*") {
		body = strings.TrimSuffix(e, "*")
		if !strings.HasSuffix(body, "/") {
			return `a final "*" must follow a "/"`
		}
	}
	if strings.Contains(body, "*") {
		return `"*" is only allowed as the last character`
	}
	if strings.ContainsAny(body, `?#\%`) {
		return "must not contain a query, fragment, backslash, or percent-encoding"
	}
	u, err := url.Parse(body)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return `must be "loopback" or an https URL`
	}
	if u.User != nil {
		return "must not contain credentials"
	}
	if msg := checkRedirectHost(u.Host); msg != "" {
		return msg
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "must include a path, such as /callback"
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "must not contain . or .. path segments"
		}
	}
	return ""
}

// hostLabelRE is one DNS label of a lowercase host name. Entries are compared
// as raw strings against what a client sends, so the syntax allows exactly one
// spelling of a host: lowercase, no trailing dot, and no IP address in any
// spelling (the last label may not be all digits or start with "0x"), nor
// "localhost" (loopback is its own entry).
var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// checkRedirectHost validates the host[:port] of a redirect allowlist entry.
func checkRedirectHost(hostport string) string {
	host := hostport
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		port := hostport[i+1:]
		n, err := strconv.Atoi(port)
		if port == "" || port[0] == '0' || len(port) > 5 || err != nil || n < 1 || n > 65535 || strings.Trim(port, "0123456789") != "" {
			return "port must be 1-65535 digits without leading zeros"
		}
	}
	if host == "" {
		return "must include a host"
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostLabelRE.MatchString(label) {
			return "host must be lowercase letters, digits, hyphens and dots, with no trailing dot"
		}
	}
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
		return "host must be a domain name, not an IP address"
	}
	if host == "localhost" {
		return `use "loopback" instead of localhost`
	}
	return ""
}
