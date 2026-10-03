package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func postRegister(t *testing.T, h http.Handler, contentType, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestRegisterPublicClient(t *testing.T) {
	s, _ := newTestStore(t)
	h := newRegistrar(s, defaultAllowlist(t))
	rec, out := postRegister(t, h, "application/json; charset=utf-8",
		`{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"Claude","token_endpoint_auth_method":"client_secret_basic","grant_types":["authorization_code"],"jwks":{"keys":[]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	id, _ := out["client_id"].(string)
	if len(id) != 26 || out["token_endpoint_auth_method"] != "none" || out["client_name"] != "Claude" || out["client_secret"] != nil {
		t.Fatalf("response = %v", out)
	}
	if gt, _ := out["grant_types"].([]any); len(gt) != 2 || gt[0] != "authorization_code" || gt[1] != "refresh_token" {
		t.Fatalf("grant_types = %v", out["grant_types"])
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	row, err := s.clientByID(id)
	if err != nil || row.Kind != kindDCR || row.Name != "Claude" || !slices.Equal(row.RedirectURIs, []string{"https://claude.ai/api/mcp/auth_callback"}) {
		t.Fatalf("stored = %+v, %v", row, err)
	}
}

func TestRegisterCleansName(t *testing.T) {
	s, _ := newTestStore(t)
	rec, out := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json",
		`{"redirect_uris":["http://127.0.0.1/callback"],"client_name":"Good\u202e App\n"}`)
	if rec.Code != http.StatusCreated || out["client_name"] != "Good App" {
		t.Fatalf("%d %v", rec.Code, out)
	}
}

func TestRegisterRejects(t *testing.T) {
	s, _ := newTestStore(t)
	for name, tc := range map[string]struct{ ct, body, code string }{
		"not allowlisted": {"application/json", `{"redirect_uris":["https://evil.example/cb"]}`, "invalid_redirect_uri"},
		"mixed":           {"application/json", `{"redirect_uris":["https://claude.ai/api/mcp/auth_callback","http://127.0.0.1/cb"]}`, "invalid_redirect_uri"},
		"none":            {"application/json", `{"client_name":"x"}`, "invalid_redirect_uri"},
		"wrong type":      {"text/plain", `{"redirect_uris":["http://127.0.0.1/cb"]}`, "invalid_client_metadata"},
		"no type":         {"", `{"redirect_uris":["http://127.0.0.1/cb"]}`, "invalid_client_metadata"},
		"not json":        {"application/json", `redirect_uris=x`, "invalid_client_metadata"},
		"array":           {"application/json", `["http://127.0.0.1/cb"]`, "invalid_client_metadata"},
		"uris as string":  {"application/json", `{"redirect_uris":"http://127.0.0.1/cb"}`, "invalid_client_metadata"},
		"too large":       {"application/json", `{"client_name":"` + strings.Repeat("a", maxRegistrationBytes) + `"}`, "invalid_client_metadata"},
	} {
		rec, out := postRegister(t, newRegistrar(s, defaultAllowlist(t)), tc.ct, tc.body)
		if rec.Code != http.StatusBadRequest || out["error"] != tc.code {
			t.Errorf("%s: %d %v", name, rec.Code, out)
		}
	}
	if n := count(t, s, `SELECT COUNT(*) FROM oauth_clients`); n != 0 {
		t.Fatalf("%d clients stored by rejected requests", n)
	}
}

func TestRegisterIsRateLimited(t *testing.T) {
	s, _ := newTestStore(t)
	h := newRegistrar(s, defaultAllowlist(t))
	body := `{"redirect_uris":["http://127.0.0.1/callback"]}`
	for i := 0; i < 5; i++ {
		if rec, _ := postRegister(t, h, "application/json", body); rec.Code != http.StatusCreated {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec, out := postRegister(t, h, "application/json", body)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || out["error"] == nil {
		t.Fatalf("6th request: %d %v", rec.Code, out)
	}
}

func TestRegisterIsCapped(t *testing.T) {
	s, clk := newTestStore(t)
	for i := 0; i < maxDCRClients; i++ {
		if err := s.insertClient(clientRow{ID: fmt.Sprintf("C%04d", i), Kind: kindDCR, Name: "n", RedirectURIs: []string{"http://127.0.0.1/cb"}, Created: clk.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	rec, out := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(out["error_description"].(string), "clients revoke") {
		t.Fatalf("%d %v", rec.Code, out)
	}
}

func FuzzParseRegistration(f *testing.F) {
	f.Add([]byte(`{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"Claude"}`))
	f.Add([]byte(`{"redirect_uris":["http://127.0.0.1:1/x"],"client_name":"\u202e"}`))
	f.Add([]byte(`{"redirect_uris":null}`))
	a := defaultAllowlist(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		r, rerr := parseRegistration(body, a)
		if rerr != nil {
			if rerr.code != "invalid_client_metadata" && rerr.code != "invalid_redirect_uri" {
				t.Fatalf("unexpected error code %q", rerr.code)
			}
			return
		}
		if len(r.RedirectURIs) == 0 || len(r.RedirectURIs) > maxRedirectURIs || r.ClientName == "" || r.ClientName != cleanName(r.ClientName) {
			t.Fatalf("accepted %+v", r)
		}
		for _, u := range r.RedirectURIs {
			if !a.allows(u) {
				t.Fatalf("accepted redirect %q", u)
			}
		}
	})
}
