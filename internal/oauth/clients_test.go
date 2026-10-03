package oauth

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// insertGrant adds a grant with one access and one refresh token, the way
// the token code (Task 8) will, so registry tests can check the cascade.
func insertGrant(t *testing.T, s *Store, family, clientID string) {
	t.Helper()
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO grants(family, client_id, scopes, audience, amr, auth_time, created, last_used) VALUES(?, ?, 'vault offline_access', 'https://x/mcp', 'otp', 1, 1, 42)`, []any{family, clientID}},
		{`INSERT INTO access_tokens(id, family, scopes, expires) VALUES(?, ?, 'vault', 9999999999)`, []any{"A" + family, family}},
		{`INSERT INTO refresh_tokens(hash, id, family, expires) VALUES(?, ?, ?, 9999999999)`, []any{hashToken("R" + family), "R" + family, family}},
	} {
		if _, err := s.db.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestClientRoundTrip(t *testing.T) {
	s, clk := newTestStore(t)
	c := clientRow{ID: "C1", Kind: kindDCR, Name: "Claude", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, Created: clk.Now()}
	if err := s.insertClient(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.clientByID("C1")
	if err != nil || got.Name != "Claude" || got.Kind != kindDCR || !slices.Equal(got.RedirectURIs, c.RedirectURIs) || !got.Created.Equal(c.Created) {
		t.Fatalf("clientByID = %+v, %v", got, err)
	}
	if _, err := s.clientByID("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
}

func TestSaveCIMDKeepsCreated(t *testing.T) {
	s, clk := newTestStore(t)
	id := "https://app.example/cimd.json"
	if err := s.saveCIMD(clientRow{ID: id, Kind: kindCIMD, Name: "A", RedirectURIs: []string{"http://127.0.0.1/cb"}, Created: clk.Now(), Fetched: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	first := clk.Now()
	clk.Advance(2 * time.Hour)
	if err := s.saveCIMD(clientRow{ID: id, Kind: kindCIMD, Name: "B", RedirectURIs: []string{"http://127.0.0.1/cb2"}, Created: clk.Now(), Fetched: clk.Now()}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.clientByID(id)
	if got.Name != "B" || got.RedirectURIs[0] != "http://127.0.0.1/cb2" || !got.Created.Equal(first) || !got.Fetched.Equal(clk.Now()) {
		t.Fatalf("after refresh = %+v", got)
	}
}

func TestListAndRevokeClients(t *testing.T) {
	s, clk := newTestStore(t)
	for _, c := range []clientRow{
		{ID: "C1", Kind: kindDCR, Name: "Claude", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, Created: clk.Now()},
		{ID: "C2", Kind: kindDCR, Name: "Code", RedirectURIs: []string{"http://127.0.0.1/callback", "http://localhost/callback"}, Created: clk.Now()},
	} {
		if err := s.insertClient(c); err != nil {
			t.Fatal(err)
		}
	}
	insertGrant(t, s, "F1", "C1")
	insertGrant(t, s, "F2", "C1")
	insertGrant(t, s, "F3", "C2")

	recs, err := s.ListClients()
	if err != nil || len(recs) != 2 {
		t.Fatalf("ListClients = %+v, %v", recs, err)
	}
	if recs[0].ID != "C1" || recs[0].Grants != 2 || recs[0].LastUsed.Unix() != 42 || !slices.Equal(recs[0].RedirectHosts, []string{"claude.ai"}) {
		t.Fatalf("C1 record = %+v", recs[0])
	}
	if !slices.Equal(recs[1].RedirectHosts, []string{"127.0.0.1", "localhost"}) {
		t.Fatalf("C2 hosts = %v", recs[1].RedirectHosts)
	}

	if err := s.RevokeClient("C1"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants WHERE client_id = 'C1'`); n != 0 {
		t.Fatalf("%d grants left for the revoked client", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM access_tokens WHERE family IN ('F1', 'F2')`) + count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE family IN ('F1', 'F2')`); n != 0 {
		t.Fatalf("%d tokens left for the revoked client", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM access_tokens WHERE family = 'F3'`); n != 1 {
		t.Fatal("revoking one client touched another")
	}
	if err := s.RevokeClient("C1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke = %v", err)
	}
}
