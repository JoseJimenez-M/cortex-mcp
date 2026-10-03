package oauth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

const testCIMD = "https://app.example.com/oauth/client.json"

func cimdBody(id, name string, uris ...string) []byte {
	q := make([]string, len(uris))
	for i, u := range uris {
		q[i] = `"` + u + `"`
	}
	return []byte(`{"client_id":"` + id + `","client_name":"` + name + `","redirect_uris":[` + strings.Join(q, ",") + `],"token_endpoint_auth_method":"none"}`)
}

func TestCheckCIMDURL(t *testing.T) {
	for _, ok := range []string{testCIMD, "https://app.example.com:443/c", "https://a.b.example/x/y.json", "https://dead.beef.example/c"} {
		if err := checkCIMDURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://app.example.com/c", "https://app.example.com", "https://app.example.com/",
		"https://app.example.com:8443/c", "https://127.0.0.1/c", "https://[::1]/c", "https://10.0.0.1/c",
		"https://user@app.example.com/c", "https://app.example.com/c?x=1", "https://app.example.com/c#f",
		"https://app.example.com/a b", "https://app.example.com/" + strings.Repeat("a", 600), "https:///c", "https://localhost/c", "https://intranet/c", "https://1.2.3.4.5/c", "https://0x7f.1/c", "https://2130706433/c", "https://0x7f000001/c", "https://a.b.0x1/c", "https://a.b.123/c",
	} {
		if checkCIMDURL(bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseCIMD(t *testing.T) {
	a := defaultAllowlist(t)
	row, err := parseCIMD(testCIMD, cimdBody(testCIMD, "My App\u202e", "http://127.0.0.1/cb"), a)
	if err != nil || row.ID != testCIMD || row.Kind != kindCIMD || row.Name != "My App" || row.RedirectURIs[0] != "http://127.0.0.1/cb" {
		t.Fatalf("parseCIMD = %+v, %v", row, err)
	}
	for name, body := range map[string][]byte{
		"id mismatch":   cimdBody("https://other.example.com/c.json", "A", "http://127.0.0.1/cb"),
		"id trailing":   cimdBody(testCIMD+"/", "A", "http://127.0.0.1/cb"),
		"no name":       cimdBody(testCIMD, " ", "http://127.0.0.1/cb"),
		"bad redirect":  cimdBody(testCIMD, "A", "https://evil.example/cb"),
		"no redirect":   cimdBody(testCIMD, "A"),
		"mixed":         cimdBody(testCIMD, "A", "http://127.0.0.1/cb", "https://claude.ai/api/mcp/auth_callback"),
		"secret client": []byte(`{"client_id":"` + testCIMD + `","client_name":"A","redirect_uris":["http://127.0.0.1/cb"],"token_endpoint_auth_method":"private_key_jwt"}`),
		"not json":      []byte("<html>"),
		"array":         []byte(`[]`),
		"null":          []byte(`null`),
	} {
		if _, err := parseCIMD(testCIMD, body, a); !errors.Is(err, errCIMD) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParseCIMD(f *testing.F) {
	f.Add(cimdBody(testCIMD, "A", "http://127.0.0.1/cb"))
	f.Add([]byte(`{"client_id":"` + testCIMD + `","client_name":"\u0000","redirect_uris":["https://chatgpt.com/connector/oauth/x"]}`))
	a := defaultAllowlist(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		row, err := parseCIMD(testCIMD, body, a)
		if err != nil {
			return
		}
		if row.ID != testCIMD || row.Name == "" || row.Name != cleanName(row.Name) || len(row.RedirectURIs) == 0 {
			t.Fatalf("accepted %+v", row)
		}
		for _, u := range row.RedirectURIs {
			if !a.allows(u) {
				t.Fatalf("accepted redirect %q", u)
			}
		}
	})
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"0.1.2.3", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1", "::1", "::", "fe80::1",
		"fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::", "2001:db8::1",
		"2001::1", "ff02::1", "::7f00:1", "::a9fe:a9fe", "fec0::1", "::ffff:0:7f00:1", "2001:2::1", "2001:10::1", "3fff::1", "5f00::1", "4000::1", "fe80::1%eth0", "::ffff:169.254.169.254", "::ffff:100.64.0.1",
	} {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "160.79.104.10", "2606:4700::1111", "2a00:1450:4001::1", "8.8.8.8"} {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
}

func TestSafeFetcherRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer ts.Close()
	_, err := newSafeFetcher().fetch(context.Background(), ts.URL+"/client.json")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the request reached a loopback server")
	}
}

func TestFetcherLimits(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/untyped", func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/doc", http.StatusFound) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, cimdMaxBytes+1)) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) { time.Sleep(500 * time.Millisecond) })
	mux.HandleFunc("/missing", http.NotFound)
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	// The test server's own transport trusts its certificate; the address
	// check is covered by TestSafeFetcherRefusesLoopback.
	f := newFetcher(ts.Client().Transport, 200*time.Millisecond)
	if body, err := f.fetch(context.Background(), ts.URL+"/doc"); err != nil || string(body) != `{"ok":true}` {
		t.Fatalf("doc = %q, %v", body, err)
	}
	for _, p := range []string{"/redirect", "/big", "/slow", "/missing", "/html", "/untyped"} {
		if _, err := f.fetch(context.Background(), ts.URL+p); err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}

type fakeFetch struct {
	calls atomic.Int32
	body  atomic.Value // []byte
	err   error
}

func (f *fakeFetch) fetch(_ context.Context, _ string) ([]byte, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.body.Load().([]byte), nil
}

func newTestResolver(t *testing.T, f *fakeFetch) (*cimdResolver, *Store, *testClock) {
	t.Helper()
	s, clk := newTestStore(t)
	return newCIMDResolver(s, defaultAllowlist(t), f.fetch, slog.New(slog.NewTextHandler(io.Discard, nil))), s, clk
}

func TestResolverCachesForAnHour(t *testing.T) {
	f := &fakeFetch{}
	f.body.Store(cimdBody(testCIMD, "First", "http://127.0.0.1/cb"))
	r, s, clk := newTestResolver(t, f)
	row, err := r.resolve(context.Background(), testCIMD)
	if err != nil || row.Name != "First" {
		t.Fatalf("resolve = %+v, %v", row, err)
	}
	if _, err := r.resolve(context.Background(), testCIMD); err != nil || f.calls.Load() != 1 {
		t.Fatalf("cached resolve: calls %d, %v", f.calls.Load(), err)
	}
	f.body.Store(cimdBody(testCIMD, "Second", "http://127.0.0.1/cb"))
	clk.Advance(cimdTTL + time.Second)
	row, err = r.resolve(context.Background(), testCIMD)
	if err != nil || row.Name != "Second" || f.calls.Load() != 2 {
		t.Fatalf("after TTL = %+v, calls %d, %v", row, f.calls.Load(), err)
	}
	if stored, _ := s.clientByID(testCIMD); stored.Name != "Second" {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestResolverRejectsBadDocumentsAndURLs(t *testing.T) {
	f := &fakeFetch{}
	f.body.Store(cimdBody("https://other.example.com/c.json", "A", "http://127.0.0.1/cb"))
	r, s, _ := newTestResolver(t, f)
	if _, err := r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
		t.Fatalf("mismatched document = %v", err)
	}
	if _, err := s.clientByID(testCIMD); !errors.Is(err, ErrNotFound) {
		t.Fatal("a rejected document was stored")
	}
	if _, err := r.resolve(context.Background(), "https://127.0.0.1/c.json"); err == nil {
		t.Fatal("IP literal resolved")
	}
	f.err = errors.New("boom")
	if _, err := r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
		t.Fatalf("fetch error = %v", err)
	}
}

func TestResolverFetchesAreRateLimited(t *testing.T) {
	f := &fakeFetch{err: errors.New("unreachable")}
	r, _, _ := newTestResolver(t, f)
	for i := 0; i < 12; i++ {
		_, _ = r.resolve(context.Background(), "https://app.example.com/c"+strings.Repeat("x", i)+".json")
	}
	if n := f.calls.Load(); n != 10 {
		t.Fatalf("%d fetches, want 10 (the burst)", n)
	}
}

func TestResolverCachesFailuresBriefly(t *testing.T) {
	f := &fakeFetch{err: errors.New("unreachable")}
	r, _, clk := newTestResolver(t, f)
	for i := 0; i < 5; i++ {
		if _, err := r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
			t.Fatalf("resolve = %v", err)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d fetches for a failing host, want 1", n)
	}
	clk.Advance(cimdFailTTL + time.Second)
	_, _ = r.resolve(context.Background(), testCIMD)
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("%d fetches after the failure expired, want 2", n)
	}
}

func TestResolverFailureCacheIsBounded(t *testing.T) {
	f := &fakeFetch{err: errors.New("unreachable")}
	r, _, _ := newTestResolver(t, f)
	r.limit = rate.NewLimiter(rate.Inf, 1)
	for i := 0; i < cimdMaxFailures+50; i++ {
		_, _ = r.resolve(context.Background(), "https://app.example.com/c"+strconv.Itoa(i)+".json")
	}
	r.mu.Lock()
	n := len(r.failed)
	r.mu.Unlock()
	if n > cimdMaxFailures {
		t.Fatalf("failure cache holds %d entries, cap %d", n, cimdMaxFailures)
	}
}

func TestResolverBoundsStoredDocuments(t *testing.T) {
	f := &fakeFetch{}
	r, s, clk := newTestResolver(t, f)
	r.limit = rate.NewLimiter(rate.Inf, 1)
	r.maxStored = 3
	for i := 0; i < 5; i++ {
		id := "https://app.example.com/c" + strconv.Itoa(i) + ".json"
		f.body.Store(cimdBody(id, "A", "http://127.0.0.1/cb"))
		if _, err := r.resolve(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Second)
	}
	if n, _ := s.countClients(kindCIMD); n != 3 {
		t.Fatalf("%d stored documents, want 3", n)
	}
	if _, err := s.clientByID("https://app.example.com/c4.json"); err != nil {
		t.Fatalf("newest document evicted: %v", err)
	}
	if _, err := s.clientByID("https://app.example.com/c0.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest document kept: %v", err)
	}
}

func TestIsCIMDClientID(t *testing.T) {
	if !isCIMDClientID(testCIMD) || isCIMDClientID("MFRGGZDFMZTWQ2LK") || isCIMDClientID("http://app.example.com/c") {
		t.Fatal("isCIMDClientID misclassified an id")
	}
}

func TestSafeFetcherRefusesLocalhostByName(t *testing.T) {
	_, err := newSafeFetcher().fetch(context.Background(), "https://localhost/client.json")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v", err)
	}
}

// grantedResolver returns a resolver holding a fetched, granted CIMD row
// whose first-time limiter is empty and whose TTL has run out.
func grantedResolver(t *testing.T) (*cimdResolver, *fakeFetch, *Store, *testClock) {
	t.Helper()
	f := &fakeFetch{}
	f.body.Store(cimdBody(testCIMD, "Old", "http://127.0.0.1/cb"))
	r, s, clk := newTestResolver(t, f)
	if _, err := r.resolve(context.Background(), testCIMD); err != nil {
		t.Fatal(err)
	}
	insertGrant(t, s, "F1", testCIMD)
	r.limit = rate.NewLimiter(0, 0)
	clk.Advance(cimdTTL + time.Second)
	return r, f, s, clk
}

func TestGrantedClientRefetchUsesItsOwnLimiter(t *testing.T) {
	r, f, _, _ := grantedResolver(t)
	f.body.Store(cimdBody(testCIMD, "New", "http://127.0.0.1/cb"))
	row, err := r.resolve(context.Background(), testCIMD)
	if err != nil || row.Name != "New" {
		t.Fatalf("refetch with a drained first-time limiter = %+v, %v", row, err)
	}
}

func TestGrantedClientServedStaleOnTransportFailure(t *testing.T) {
	r, f, _, clk := grantedResolver(t)
	f.err = errors.New("boom")
	row, err := r.resolve(context.Background(), testCIMD)
	if err != nil || row.Name != "Old" {
		t.Fatalf("within 24h = %+v, %v", row, err)
	}
	r.refetch = rate.NewLimiter(0, 0)
	r.failed = map[string]time.Time{}
	if row, err = r.resolve(context.Background(), testCIMD); err != nil || row.Name != "Old" {
		t.Fatalf("rate limited = %+v, %v", row, err)
	}
	clk.Advance(cimdStaleMax)
	r.failed = map[string]time.Time{}
	if _, err = r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
		t.Fatalf("beyond 24h = %v", err)
	}
}

func TestUngrantedClientNotServedStale(t *testing.T) {
	f := &fakeFetch{}
	f.body.Store(cimdBody(testCIMD, "Old", "http://127.0.0.1/cb"))
	r, _, clk := newTestResolver(t, f)
	if _, err := r.resolve(context.Background(), testCIMD); err != nil {
		t.Fatal(err)
	}
	clk.Advance(cimdTTL + time.Second)
	f.err = errors.New("boom")
	if _, err := r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidRefetchedDocumentDropsTheClient(t *testing.T) {
	r, f, s, _ := grantedResolver(t)
	f.body.Store(cimdBody(testCIMD, "Evil", "https://evil.example/cb"))
	if _, err := r.resolve(context.Background(), testCIMD); !errors.Is(err, errCIMD) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.clientByID(testCIMD); !errors.Is(err, ErrNotFound) {
		t.Fatalf("row kept: %v", err)
	}
	if n := countRows(t, s, "grants"); n != 0 {
		t.Fatalf("%d grants kept", n)
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRateLimitLogIsAggregatedAndOmitsIDs(t *testing.T) {
	var buf strings.Builder
	f := &fakeFetch{err: errors.New("unreachable")}
	s, _ := newTestStore(t)
	r := newCIMDResolver(s, defaultAllowlist(t), f.fetch, slog.New(slog.NewTextHandler(&buf, nil)))
	r.limit = rate.NewLimiter(0, 0)
	for i := 0; i < 5; i++ {
		_, _ = r.resolve(context.Background(), "https://app.example.com/secret"+strconv.Itoa(i)+".json")
	}
	out := buf.String()
	if strings.Contains(out, "secret") || strings.Count(out, "rate limit") != 1 {
		t.Fatalf("log = %q", out)
	}
}
