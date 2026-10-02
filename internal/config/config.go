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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

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
	Limits           Limits   `yaml:"limits"`
	Logs             Logs     `yaml:"logs"`
}

// Default returns the defaults; Load decodes the file on top of them, so a
// key missing from the file keeps its default.
func Default() Config {
	return Config{
		Listen:       ":8080",
		BearerTokens: true,
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
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
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

func isLocalHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

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
	if c.InstructionsFile != "" && (!filepath.IsLocal(c.InstructionsFile) || !strings.EqualFold(filepath.Ext(c.InstructionsFile), ".md")) {
		add("instructions_file: must be a .md file inside the vault")
	}
	for i, d := range c.Deny {
		if msg := checkDeny(d); msg != "" {
			add("deny[%d] (%q): %s", i, d, msg)
		}
	}
	if !c.BearerTokens {
		add("bearer_tokens: cannot be false until OAuth is implemented, or no client could authenticate")
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
	const hint = "must be an https URL with only a host (http is allowed only for localhost)"
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return hint
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocalHost(u.Hostname())) {
		return hint
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
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "port must be a number from 1 to 65535"
	}
	return ""
}

func checkDeny(d string) string {
	switch {
	case d == "":
		return "must not be empty"
	case d != strings.TrimSpace(d):
		return "must not have leading or trailing whitespace"
	case filepath.IsAbs(d) || strings.HasPrefix(d, "/"):
		return "must be relative to the vault"
	case strings.Contains(d, `\`):
		return "must not contain a backslash"
	case strings.IndexFunc(d, unicode.IsControl) >= 0:
		return "must not contain control characters"
	}
	for _, seg := range strings.Split(d, "/") {
		if seg == ".." {
			return `must not contain ".."`
		}
	}
	return ""
}
