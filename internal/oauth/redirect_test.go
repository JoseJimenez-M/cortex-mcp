package oauth

import (
	"net/url"
	"strings"
	"testing"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

func defaultAllowlist(t testing.TB) allowlist {
	t.Helper()
	a, err := parseAllowlist(config.DefaultRedirectAllowlist())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAllowlistMatching(t *testing.T) {
	a := defaultAllowlist(t)
	for _, u := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector_platform_oauth_redirect",
		"https://chatgpt.com/connector/oauth/AbC_123-x.y",
		"https://agent.meta.ai/api/hatch/oauth/callback",
		"http://localhost/callback",
		"http://127.0.0.1:53682/callback",
		"http://[::1]:8080/cb?x=1",
	} {
		if !a.allows(u) {
			t.Errorf("refused %q", u)
		}
	}
	for _, u := range []string{
		"",
		"https://claude.ai/api/mcp/auth_callback/",
		"https://claude.ai/api/mcp/auth_callback?x=1",
		"https://CLAUDE.ai/api/mcp/auth_callback",
		"https://claude.ai./api/mcp/auth_callback",
		"https://claude.ai:443/api/mcp/auth_callback",
		"https://user@claude.ai/api/mcp/auth_callback",
		"https://claude.ai/api/mcp/auth_callback#f",
		"https://claude.ai/api/mcp/auth%5fcallback",
		"https://claude.ai.evil.com/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/",
		"https://chatgpt.com/connector/oauth/a/b",
		"https://chatgpt.com/connector/oauth/..",
		"https://chatgpt.com/connector/oauth/.x",
		"https://chatgpt.com/connector/oauth/a%2Fb",
		"https://chatgpt.com/connector/oauth/%61",
		"https://chatgpt.com/connector/oauth/a?x",
		"https://chatgpt.com/connector/oauth/a#x",
		"http://claude.ai/api/mcp/auth_callback",
		"http://localhost.evil.com/cb",
		"http://user@localhost/cb",
		"http://127.0.0.2/cb",
		"http://localhost:0/cb",
		"http://localhost:/cb",
		"http://localhost:99999/cb",
		"http://localhost/cb#x",
		"http://LOCALHOST/cb",
		"HTTP://localhost/cb",
		"hTtP://127.0.0.1/cb",
		"http://localhost./cb",
		"http://localhost/%2e%2e/cb",
		"http://localhost/a/../cb",
		"http://localhost/./cb",
		`http://localhost\@evil.com/cb`,
		"https://localhost/cb",
		"javascript:alert(1)",
		"https://claude.ai/api/mcp/auth_callback" + strings.Repeat("x", 600),
	} {
		if a.allows(u) {
			t.Errorf("allowed %q", u)
		}
	}
}

func TestAllowlistWithoutLoopback(t *testing.T) {
	a, err := parseAllowlist([]string{"https://example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if a.allows("http://127.0.0.1/cb") || !a.allows("https://example.com/cb") {
		t.Fatal("loopback must need the loopback entry")
	}
}

func TestParseAllowlistRejectsBadEntries(t *testing.T) {
	if _, err := parseAllowlist([]string{"loopback", "http://example.com/cb"}); err == nil || !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("err = %v", err)
	}
	for _, e := range []string{"https://Example.com/cb", "https://example.com./cb", "https://x:/cb", "https://a,b.com/cb", "https://example.com/%2e"} {
		if _, err := parseAllowlist([]string{e}); err == nil {
			t.Errorf("accepted %q", e)
		}
	}
}

func TestCheckRedirectSet(t *testing.T) {
	a := defaultAllowlist(t)
	if native, err := a.checkRedirectSet([]string{"http://127.0.0.1/callback", "http://localhost/callback"}); err != nil || !native {
		t.Fatalf("loopback set = %v, %v", native, err)
	}
	if native, err := a.checkRedirectSet([]string{"https://claude.ai/api/mcp/auth_callback"}); err != nil || native {
		t.Fatalf("https set = %v, %v", native, err)
	}
	for name, set := range map[string][]string{
		"empty":   nil,
		"mixed":   {"https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1/callback"},
		"refused": {"https://evil.example/cb"},
		"too many": {
			"http://127.0.0.1/1", "http://127.0.0.1/2", "http://127.0.0.1/3", "http://127.0.0.1/4", "http://127.0.0.1/5", "http://127.0.0.1/6",
			"http://127.0.0.1/7", "http://127.0.0.1/8", "http://127.0.0.1/9", "http://127.0.0.1/10", "http://127.0.0.1/11",
		},
	} {
		if _, err := a.checkRedirectSet(set); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func dotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// FuzzAllowlist checks the property the allowlist exists for: whatever the
// input, an allowed URI goes to one of the configured hosts, with no
// credentials, fragment, or dot segments.
func FuzzAllowlist(f *testing.F) {
	for _, s := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://chatgpt.com/connector/oauth/abc",
		"http://127.0.0.1:3000/callback",
		"https://chatgpt.com/connector/oauth/../x",
		"http://localhost@evil.com/",
		"https://claude.ai/api/mcp/auth_callback?x=1",
	} {
		f.Add(s)
	}
	a := defaultAllowlist(f)
	hosts := map[string]bool{"claude.ai": true, "chatgpt.com": true, "agent.meta.ai": true, "localhost": true, "127.0.0.1": true, "::1": true}
	f.Fuzz(func(t *testing.T, uri string) {
		if !a.allows(uri) {
			return
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("allowed unparsable %q", uri)
		}
		if !hosts[u.Hostname()] || u.User != nil || u.Fragment != "" || strings.ContainsAny(uri, "#\\%") {
			t.Fatalf("allowed %q (host %q)", uri, u.Hostname())
		}
		if dotSegment(u.Path) {
			t.Fatalf("allowed dot segment in %q", uri)
		}
		switch u.Scheme {
		case "https":
			if u.RawQuery != "" || u.Port() != "" {
				t.Fatalf("allowed https %q with a query or port", uri)
			}
		case "http":
			if !isLoopbackRedirect(uri) {
				t.Fatalf("allowed non-loopback http %q", uri)
			}
		default:
			t.Fatalf("allowed scheme %q", u.Scheme)
		}
	})
}

// FuzzAllowlistEntry fuzzes both sides: any entry the config accepts, and any
// URI. If the matcher allows the URI, it must start with the entry's literal
// prefix, share its scheme and host, and carry no userinfo or dot segments,
// so the config syntax and the matcher cannot disagree.
func FuzzAllowlistEntry(f *testing.F) {
	for _, e := range []string{"https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector/oauth/*", "https://example.com:8443/cb", "loopback"} {
		for _, u := range []string{e, strings.TrimSuffix(e, "*") + "abc", "https://chatgpt.com/connector/oauth/../x", "http://localhost:80/cb", "https://example.com:8443/cb"} {
			f.Add(e, u)
		}
	}
	f.Fuzz(func(t *testing.T, entry, uri string) {
		a, err := parseAllowlist([]string{entry})
		if err != nil || !a.allows(uri) {
			return
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("allowed unparsable %q", uri)
		}
		if u.User != nil || u.Fragment != "" || strings.ContainsAny(uri, "#\\%") || dotSegment(u.Path) {
			t.Fatalf("allowed %q for %q: userinfo, fragment, escape or dot segment", uri, entry)
		}
		if entry == "loopback" {
			if !isLoopbackRedirect(uri) {
				t.Fatalf("loopback entry allowed %q", uri)
			}
			return
		}
		prefix := strings.TrimSuffix(entry, "*")
		if !strings.HasPrefix(uri, prefix) {
			t.Fatalf("allowed %q outside prefix of %q", uri, entry)
		}
		e, err := url.Parse(prefix)
		if err != nil || u.Scheme != e.Scheme || u.Host != e.Host {
			t.Fatalf("allowed %q with another scheme or host than %q", uri, entry)
		}
	})
}
