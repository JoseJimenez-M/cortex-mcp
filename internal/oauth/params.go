package oauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// The parameters each library endpoint is allowed to see, in their only
// accepted spelling. The library's form decoder (zitadel/schema) matches
// keys with strings.EqualFold and walks the form map in random order, so
// "REDIRECT_URI" could override the "redirect_uri" our checks looked at.
// canonicalForm hands the library only these exact keys.
var (
	authorizeParams = []string{"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
		"nonce", "prompt", "code_challenge", "code_challenge_method", "resource"}
	tokenParams  = []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "refresh_token", "scope", "resource"}
	revokeParams = []string{"token", "token_type_hint", "client_id"}
)

// canonicalForm replaces the parsed form of r with only the known keys,
// spelled exactly. It refuses a request with a key that case-folds to a
// known one without being it, or a known key given more than once (in the
// query, the body, or across both); resource is the one key RFC 8707 lets
// repeat, and resourceOK refuses more than one value itself. Other keys
// are dropped. The raw query and body are cleared, so nothing downstream
// can read the original values: the library's ParseForm is a no-op once
// Form and PostForm are set, and r.URL.Query() is empty.
func canonicalForm(r *http.Request, known []string) bool {
	clean := url.Values{}
	for k, v := range r.Form {
		if slices.Contains(known, k) {
			if len(v) > 1 && k != "resource" {
				return false
			}
			clean[k] = v
			continue
		}
		for _, n := range known {
			if strings.EqualFold(k, n) {
				return false
			}
		}
	}
	u := *r.URL
	u.RawQuery, u.ForceQuery = "", false
	r.URL, r.RequestURI = &u, u.RequestURI()
	// PostForm must be non-nil too: net/http's ParseForm, which the library
	// calls again, re-reads the body whenever PostForm is nil. It gets the
	// same clean values (not the original), so code that reads PostForm
	// directly never sees a spelling canonicalForm refused or dropped.
	r.Form, r.PostForm, r.MultipartForm = clean, clean, nil
	r.Body = http.NoBody
	return true
}

// preCheck runs before the library sees an authorization request. The
// library validates scope, prompt, and response_type after it accepted the
// redirect URI, and for a native client it accepts any loopback URI with
// the registered path (userinfo, 127.0.0.2, https, IPv4-mapped forms), then
// redirects its own errors there. Resolving the client and applying our
// allowlist first means no response of any kind is ever redirected to a
// URI the allowlist refuses. The messages are fixed text.
func (s *Service) preCheck(r *http.Request) (string, bool) {
	if r.Form.Get("response_type") != string(oidc.ResponseTypeCode) {
		return "unsupported response_type: only code is supported", false
	}
	if m := r.Form.Get("response_mode"); m != "" && m != string(oidc.ResponseModeQuery) {
		return "unsupported response_mode: only query is supported", false
	}
	if _, err := s.op.GetClientByClientID(r.Context(), r.Form.Get("client_id")); err != nil {
		return "unknown client: start the connection again from the assistant", false
	}
	if !s.allow.allows(r.Form.Get("redirect_uri")) {
		return "the redirect_uri is not allowed by this server", false
	}
	if !s.resourceOK(r.Form["resource"]) {
		return "invalid_target: resource must be " + s.mcpURL, false
	}
	return "", true
}

// issWriter adds the RFC 9207 iss parameter to every redirect that leaves
// this server (authorization responses, success or error). Redirects to our
// own pages (the login page) are left alone.
type issWriter struct {
	http.ResponseWriter
	iss   string
	wrote bool
}

func (w *issWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code >= 300 && code < 400 {
			w.addIss()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *issWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *issWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *issWriter) addIss() {
	loc := w.Header().Get("Location")
	if loc == "" || strings.HasPrefix(loc, "/") || loc == w.iss || strings.HasPrefix(loc, w.iss+"/") {
		return
	}
	// The client's query bytes are kept as they are (re-encoding would
	// reorder them and change escapes); only an existing iss pair is
	// dropped before ours is appended. Authorization responses here are
	// query mode only, but a fragment is kept after the query if present.
	rest, frag, hasFrag := strings.Cut(loc, "#")
	base, query, _ := strings.Cut(rest, "?")
	var pairs []string
	if query != "" {
		for _, p := range strings.Split(query, "&") {
			if k, _, _ := strings.Cut(p, "="); k != "iss" {
				pairs = append(pairs, p)
			}
		}
	}
	pairs = append(pairs, "iss="+url.QueryEscape(w.iss))
	loc = base + "?" + strings.Join(pairs, "&")
	if hasFrag {
		loc += "#" + frag
	}
	w.Header().Set("Location", loc)
}
