// Package oauth is the built-in OAuth 2.1 authorization server (spec 6.2):
// owner credentials and login, client registration (DCR and client ID
// metadata documents), and the token store, around the protocol core of
// github.com/zitadel/oidc/v3/pkg/op. Read AGENTS.md in this folder first.
package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

const (
	// maxRedirectURIBytes bounds every redirect URI a client presents.
	maxRedirectURIBytes = 512
	// maxRedirectURIs bounds the redirect URIs of one client.
	maxRedirectURIs = 10
)

// segmentRE is the one path segment a prefix entry ("https://host/path/*")
// admits, such as ChatGPT's callback id. It cannot start with a dot, so "."
// and ".." never match, and it has no "/", "?", "#", "%" or "\", so the URI
// cannot leave the prefix's path, smuggle a query, or hide an encoded slash.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,127}$`)

// allowlist is the parsed redirect allowlist (spec 6.2). It is applied when a
// client registers (DCR) or is fetched (CIMD), and again every time the
// client is loaded, so a tighter config takes effect for existing clients.
type allowlist struct {
	exact    map[string]bool
	prefixes []string
	loopback bool
}

// parseAllowlist builds the matcher. Syntax errors come from
// config.CheckRedirectEntry, the function config validation uses, so the
// two can never disagree.
func parseAllowlist(entries []string) (allowlist, error) {
	a := allowlist{exact: map[string]bool{}}
	for i, e := range entries {
		if msg := config.CheckRedirectEntry(e); msg != "" {
			return allowlist{}, fmt.Errorf("redirect allowlist entry %d (%q): %s", i, e, msg)
		}
		switch {
		case e == "loopback":
			a.loopback = true
		case strings.HasSuffix(e, "*"):
			a.prefixes = append(a.prefixes, strings.TrimSuffix(e, "*"))
		default:
			a.exact[e] = true
		}
	}
	return a, nil
}

// allows reports whether a client may use uri as a redirect URI. Entries
// satisfy config.CheckRedirectEntry's character rules (lowercase host, no
// trailing dot, no percent-encoding, no userinfo or fragment). Exact entries
// compare the raw string, with no normalization, so this check and the
// browser can never parse the URI differently; a URI that only matches after
// normalizing is refused, not rewritten. Loopback URIs follow
// isLoopbackRedirect; a prefix entry admits exactly one safe segment.
func (a allowlist) allows(uri string) bool {
	if uri == "" || len(uri) > maxRedirectURIBytes {
		return false
	}
	if a.exact[uri] {
		return true
	}
	if isLoopbackRedirect(uri) {
		return a.loopback
	}
	for _, p := range a.prefixes {
		if rest, ok := strings.CutPrefix(uri, p); ok && segmentRE.MatchString(rest) {
			return true
		}
	}
	return false
}

// isLoopbackRedirect reports whether uri is a native-client redirect: http on
// localhost, 127.0.0.1 or [::1], any port (RFC 8252 section 7.3), with no
// credentials, fragment, percent-encoding or dot segments. The host must
// already be in its lowercase, no-trailing-dot form. Only these three hosts
// count, not all of 127.0.0.0/8, which keeps the rule easy to state and to
// audit.
func isLoopbackRedirect(uri string) bool {
	if len(uri) > maxRedirectURIBytes {
		return false
	}
	for _, r := range uri {
		if r <= ' ' || r >= 0x7f || r == '%' || r == '#' || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return false
	}
	host, hostport := u.Hostname(), u.Host
	switch host {
	case "localhost", "127.0.0.1":
		if hostport != host && !validPortSuffix(strings.TrimPrefix(hostport, host)) {
			return false
		}
	case "::1":
		if hostport != "[::1]" && !validPortSuffix(strings.TrimPrefix(hostport, "[::1]")) {
			return false
		}
	default:
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validPortSuffix accepts ":N" with N in 1-65535, digits only.
func validPortSuffix(s string) bool {
	p, ok := strings.CutPrefix(s, ":")
	if !ok || p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// checkRedirectSet validates the redirect URIs of one client: 1 to 10, each
// allowed, and either all loopback (a native client) or none, because the
// library decides per client whether any loopback port is acceptable. The
// error text goes back to the client and never echoes its input.
func (a allowlist) checkRedirectSet(uris []string) (native bool, err error) {
	if len(uris) == 0 || len(uris) > maxRedirectURIs {
		return false, fmt.Errorf("between 1 and %d redirect_uris are required", maxRedirectURIs)
	}
	loop := 0
	for _, u := range uris {
		if !a.allows(u) {
			return false, errors.New("a redirect URI is not on this server's redirect allowlist")
		}
		if isLoopbackRedirect(u) {
			loop++
		}
	}
	if loop != 0 && loop != len(uris) {
		return false, errors.New("redirect_uris must be all loopback or all https")
	}
	return loop == len(uris), nil
}
