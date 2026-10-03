package oauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	for i := 0; i < 10; i++ {
		if rec, _ := postRegister(t, h, "application/json", body); rec.Code != http.StatusCreated {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec, out := postRegister(t, h, "application/json", body)
	ra, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if rec.Code != http.StatusTooManyRequests || err != nil || ra < 1 || ra > 60 || out["error"] == nil {
		t.Fatalf("11th request: %d %q %v", rec.Code, rec.Header().Get("Retry-After"), out)
	}
}

func TestJunkDoesNotConsumeTheLimiter(t *testing.T) {
	s, _ := newTestStore(t)
	h := newRegistrar(s, defaultAllowlist(t))
	for i := 0; i < 100; i++ {
		body := `{"redirect_uris":["https://evil.example/cb"]}`
		if i%2 == 0 {
			body = `not json`
		}
		if rec, _ := postRegister(t, h, "application/json", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("junk %d: %d", i, rec.Code)
		}
	}
	if rec, _ := postRegister(t, h, "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("valid registration after junk: %d", rec.Code)
	}
}

func seedUnused(t *testing.T, s *Store, n int, created time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.insertClient(clientRow{ID: fmt.Sprintf("U%04d", i), Kind: kindDCR, Name: "n", RedirectURIs: []string{"http://127.0.0.1/cb"}, Created: created.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFullTableEvictsOldestEligibleUnusedClient(t *testing.T) {
	s, clk := newTestStore(t)
	seedUnused(t, s, maxUnusedDCR, clk.Now())
	clk.Advance(authRequestTTL + time.Hour)
	rec, _ := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("51st: %d %s", rec.Code, rec.Body)
	}
	if _, err := s.clientByID("U0000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest was not evicted: %v", err)
	}
	if _, err := s.clientByID("U0001"); err != nil {
		t.Fatalf("second oldest evicted: %v", err)
	}
	if n, _ := s.countClients(kindDCR); n != maxUnusedDCR {
		t.Fatalf("%d clients", n)
	}
}

func TestClientsWithGrantsAreNeverEvictedOrCounted(t *testing.T) {
	s, clk := newTestStore(t)
	seedUnused(t, s, maxUnusedDCR, clk.Now())
	for i := 0; i < maxUnusedDCR; i++ {
		insertGrant(t, s, fmt.Sprintf("F%d", i), fmt.Sprintf("U%04d", i))
	}
	clk.Advance(authRequestTTL + time.Hour)
	// All 50 have grants, so none counts and registration just inserts.
	for i := 0; i < 3; i++ {
		if rec, _ := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`); rec.Code != http.StatusCreated {
			t.Fatalf("registration %d: %d", i, rec.Code)
		}
	}
	if n := count(t, s, `SELECT COUNT(*) FROM oauth_clients WHERE id LIKE 'U%'`); n != maxUnusedDCR {
		t.Fatalf("a client with a grant was evicted: %d left", n)
	}
}

func TestYoungClientsAreNotEvicted(t *testing.T) {
	s, clk := newTestStore(t)
	seedUnused(t, s, maxUnusedDCR, clk.Now())
	clk.Advance(authRequestTTL / 2)
	rec, out := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`)
	if rec.Code != http.StatusServiceUnavailable || out["error"] != "temporarily_unavailable" || strings.Contains(rec.Body.String(), "cortex-mcp") {
		t.Fatalf("%d %v", rec.Code, out)
	}
	if n, _ := s.countClients(kindDCR); n != maxUnusedDCR {
		t.Fatalf("%d clients", n)
	}
}

func TestConcurrentRegistrationsRespectTheCap(t *testing.T) {
	s, clk := newTestStore(t)
	seedUnused(t, s, maxUnusedDCR-5, clk.Now())
	var wg sync.WaitGroup
	var ok, full atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.registerDCR(clientRow{ID: rand.Text(), Kind: kindDCR, Name: "n", RedirectURIs: []string{"http://127.0.0.1/cb"}, Created: clk.Now()}, maxUnusedDCR, authRequestTTL)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, errRegistryFull):
				full.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 || full.Load() != 15 {
		t.Fatalf("ok=%d full=%d", ok.Load(), full.Load())
	}
	if n, _ := s.countClients(kindDCR); n != maxUnusedDCR {
		t.Fatalf("%d clients", n)
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

// An attacker alone is limited by the registration rate. For a 503 the table
// must be full of clients younger than authRequestTTL, so what the limiter
// admits within that window has to stay below the cap.
func TestRegistrationRateCannotFillTheTableWithYoungClients(t *testing.T) {
	s, _ := newTestStore(t)
	l := newRegistrar(s, defaultAllowlist(t)).limit
	window := int(float64(l.Limit()) * authRequestTTL.Seconds())
	if l.Burst()+window >= maxUnusedDCR {
		t.Fatalf("burst %d + rate over %v (%d) must stay below maxUnusedDCR (%d)", l.Burst(), authRequestTTL, window, maxUnusedDCR)
	}
}

func TestOwnerApprovedLoginIsNotEvicted(t *testing.T) {
	s, clk := newTestStore(t)
	seedUnused(t, s, maxUnusedDCR, clk.Now())
	clk.Advance(authRequestTTL + time.Minute)
	// The owner approved a login for the oldest client a moment ago.
	if err := s.createAuthRequest(&authRequest{ID: "R1", ClientID: "U0000", CSRF: "c", Family: "F", Browser: "b", Created: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.completeAuthRequest("R1", "otp"); err != nil {
		t.Fatal(err)
	}
	// A pending (unapproved) request on the next one pins nothing.
	if err := s.createAuthRequest(&authRequest{ID: "R2", ClientID: "U0001", CSRF: "c", Family: "G", Browser: "b", Created: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	if rec, _ := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("registration: %d", rec.Code)
	}
	if _, err := s.clientByID("U0000"); err != nil {
		t.Fatalf("client with an approved login was evicted: %v", err)
	}
	if _, err := s.clientByID("U0001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("client with only a pending request survived: %v", err)
	}
	// Once the approval itself is older than the TTL it protects nothing.
	clk.Advance(authRequestTTL)
	if rec, _ := postRegister(t, newRegistrar(s, defaultAllowlist(t)), "application/json", `{"redirect_uris":["http://127.0.0.1/callback"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("registration: %d", rec.Code)
	}
	if _, err := s.clientByID("U0000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired approval still pins its client: %v", err)
	}
}
