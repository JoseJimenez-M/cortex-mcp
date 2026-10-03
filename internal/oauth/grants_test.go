package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// issue runs a code exchange's storage calls and returns the access token
// id and the refresh token.
func issue(t *testing.T, o *opStorage, clientID string) (string, string, *authRequest) {
	t.Helper()
	a := redeem(t, o, clientID)
	id, refresh, exp, err := o.CreateAccessAndRefreshTokens(context.Background(), a, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := o.s.now().Add(accessTTL); !exp.Equal(want) {
		t.Fatalf("access expiry = %v, want %v", exp, want)
	}
	return id, refresh, a
}

// redeem runs the library's steps before the token call: save the code,
// then redeem it (which marks it used).
func redeem(t *testing.T, o *opStorage, clientID string) *authRequest {
	t.Helper()
	a := newApproved(t, o, clientID, "http://127.0.0.1/callback")
	code := rand.Text()
	if err := o.SaveAuthCode(context.Background(), a.ID, code); err != nil {
		t.Fatal(err)
	}
	got, err := o.AuthRequestByCode(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	return got.(*authRequest)
}

func refreshOnce(t *testing.T, o *opStorage, refresh string) (string, string) {
	t.Helper()
	req, err := o.TokenRequestByRefreshToken(context.Background(), refresh)
	if err != nil {
		t.Fatal(err)
	}
	id, next, _, err := o.CreateAccessAndRefreshTokens(context.Background(), req, refresh)
	if err != nil {
		t.Fatal(err)
	}
	return id, next
}

func TestCodeExchangeIssuesBoundTokens(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	id, refresh, a := issue(t, o, "C")
	if !wellFormedRefresh(refresh) || strings.Contains(refresh, a.Family) {
		t.Fatalf("refresh token %q", refresh)
	}
	info, err := s.lookupAccess(id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Family != a.Family || info.ClientID != "C" || info.ClientName != "Test C" ||
		strings.Join(info.Scopes, " ") != "vault offline_access" || len(info.Audience) != 1 || info.Audience[0] != "https://cortex.example/mcp" {
		t.Fatalf("access info = %+v", info)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE hash = ?`, hashToken(refresh)); n != 1 {
		t.Fatal("refresh token not stored by hash")
	}
}

func TestRefreshRotatesAndKeepsTheFamily(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	id1, r1, a := issue(t, o, "C")
	id2, r2 := refreshOnce(t, o, r1)
	if r2 == r1 || id2 == id1 {
		t.Fatal("refresh did not rotate")
	}
	info, err := s.lookupAccess(id2)
	if err != nil || info.Family != a.Family {
		t.Fatalf("new access token = %+v, %v", info, err)
	}
	if _, err := s.lookupAccess(id1); err != nil {
		t.Fatal("rotation must not revoke the previous access token before it expires")
	}
}

func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, r1, a := issue(t, o, "C")
	id2, r2 := refreshOnce(t, o, r1)
	if _, err := o.TokenRequestByRefreshToken(context.Background(), r1); !errors.Is(err, errRefreshReused) {
		t.Fatalf("reuse = %v", err)
	}
	if _, err := o.TokenRequestByRefreshToken(context.Background(), r2); err == nil {
		t.Fatal("the family's newest refresh token survived reuse")
	}
	if _, err := s.lookupAccess(id2); !errors.Is(err, ErrNotFound) {
		t.Fatal("the family's access token survived reuse")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants WHERE family = ?`, a.Family); n != 0 {
		t.Fatal("grant survived reuse")
	}
}

// Two requests that both read the same refresh token before either rotates
// it: the second rotation finds it rotated and revokes the family.
func TestRacingRotationsRevokeTheFamily(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, r1, _ := issue(t, o, "C")
	req1, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
	req2, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
	id, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), req1, r1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), req2, r1); !errors.Is(err, errRefreshReused) {
		t.Fatalf("second rotation = %v", err)
	}
	if _, err := s.lookupAccess(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("family survived a racing rotation")
	}
}

func TestRefreshExpiresAfter30Days(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, r1, _ := issue(t, o, "C")
	clk.Advance(refreshTTL)
	if _, err := o.TokenRequestByRefreshToken(context.Background(), r1); !errors.Is(err, errInvalidRefresh) {
		t.Fatalf("expired refresh = %v", err)
	}
}

func TestRefreshFailsAfterClientRevoked(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	id, r1, _ := issue(t, o, "C")
	if err := s.RevokeClient("C"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.TokenRequestByRefreshToken(context.Background(), r1); err == nil {
		t.Fatal("refresh works after the client was revoked")
	}
	if _, err := s.lookupAccess(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("access works after the client was revoked")
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	id, _, _ := issue(t, o, "C")
	info, _ := s.lookupAccess(id)
	clk.Advance(accessTTL)
	if !info.Expires.Equal(clk.Now()) {
		t.Fatalf("expires %v, now %v", info.Expires, clk.Now())
	}
}

func TestRevokeToken(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	addClient(t, s, "D", "http://127.0.0.1/callback")
	id, refresh, _ := issue(t, o, "C")
	if e := o.RevokeToken(context.Background(), id, ownerSubject, "D"); e == nil || e.ErrorType != oidc.InvalidClient {
		t.Fatalf("revoke by another client = %v", e)
	}
	if e := o.RevokeToken(context.Background(), "unknown", "", "C"); e != nil {
		t.Fatalf("unknown token = %v (RFC 7009 says 200)", e)
	}
	_, refreshID, err := o.GetRefreshTokenInfo(context.Background(), "C", refresh)
	if err != nil {
		t.Fatal(err)
	}
	if e := o.RevokeToken(context.Background(), refreshID, ownerSubject, "C"); e != nil {
		t.Fatal(e)
	}
	if _, err := s.lookupAccess(id); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoking the refresh token left the family's access token")
	}
	// A raw refresh token (what /revoke passes when the hint is wrong) works too.
	id2, refresh2, _ := issue(t, o, "C")
	if e := o.RevokeToken(context.Background(), refresh2, "", "C"); e != nil {
		t.Fatal(e)
	}
	if _, err := s.lookupAccess(id2); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoking a raw refresh token left the family")
	}
}

func TestGetRefreshTokenInfo(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	for _, bad := range []string{"", "eyJhbGciOiJ.x.y", refreshPrefix + "short", refreshPrefix + strings.Repeat("A", 43)} {
		if _, _, err := o.GetRefreshTokenInfo(context.Background(), "C", bad); !errors.Is(err, op.ErrInvalidRefreshToken) {
			t.Errorf("%q = %v", bad, err)
		}
	}
	_, refresh, _ := issue(t, o, "C")
	if sub, id, err := o.GetRefreshTokenInfo(context.Background(), "C", refresh); err != nil || sub != ownerSubject || id == "" || id == refresh {
		t.Fatalf("info = %q %q %v", sub, id, err)
	}
}

func TestSweepRemovesExpiredTokensAndEmptyGrants(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, _, _ = issue(t, o, "C")
	clk.Advance(refreshTTL + time.Minute)
	s.lastSweep.Store(0)
	s.sweep()
	for _, table := range []string{"access_tokens", "refresh_tokens", "grants"} {
		if n := count(t, s, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Errorf("%s: %d rows left", table, n)
		}
	}
}

func familyRows(t *testing.T, s *Store, family string) int {
	t.Helper()
	n := 0
	for _, table := range []string{"auth_codes", "access_tokens", "refresh_tokens", "grants"} {
		n += count(t, s, `SELECT COUNT(*) FROM `+table+` WHERE family = ?`, family)
	}
	return n
}

// There are no foreign keys, so every revocation path must delete the
// family's rows from all four tables itself.
func TestEveryRevocationPathLeavesNoFamilyRows(t *testing.T) {
	ctx := context.Background()
	paths := map[string]func(o *opStorage, s *Store, refresh string, a *authRequest){
		"code replay": nil, // handled below: it replays the code itself
		"refresh reuse": func(o *opStorage, _ *Store, refresh string, _ *authRequest) {
			refreshOnce(t, o, refresh)
			_, _ = o.TokenRequestByRefreshToken(ctx, refresh)
		},
		"revoke endpoint": func(o *opStorage, _ *Store, refresh string, _ *authRequest) {
			if e := o.RevokeToken(ctx, refresh, "", "C"); e != nil {
				t.Fatal(e)
			}
		},
		"client revoke": func(_ *opStorage, s *Store, _ string, _ *authRequest) {
			if err := s.RevokeClient("C"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, revoke := range paths {
		t.Run(name, func(t *testing.T) {
			o, s, _ := newTestOP(t)
			addClient(t, s, "C", "http://127.0.0.1/callback")
			code := rand.Text()
			a := newApproved(t, o, "C", "http://127.0.0.1/callback")
			if err := o.SaveAuthCode(ctx, a.ID, code); err != nil {
				t.Fatal(err)
			}
			if _, err := o.AuthRequestByCode(ctx, code); err != nil {
				t.Fatal(err)
			}
			_, refresh, _, err := o.CreateAccessAndRefreshTokens(ctx, a, "")
			if err != nil {
				t.Fatal(err)
			}
			if familyRows(t, s, a.Family) < 4 {
				t.Fatal("setup left fewer rows than expected")
			}
			if name == "code replay" {
				if _, err := o.AuthRequestByCode(ctx, code); err == nil {
					t.Fatal("replay accepted")
				}
			} else {
				revoke(o, s, refresh, a)
			}
			if n := familyRows(t, s, a.Family); n != 0 {
				t.Fatalf("%d rows survived revocation", n)
			}
		})
	}
}

// A replay of the code that lands between redemption and the grant insert
// revokes the family (deleting the code row); the insert must then fail
// instead of creating a grant nothing can revoke.
func TestCodeReplayRacingTheExchangeLeavesNoGrant(t *testing.T) {
	ctx := context.Background()
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	if err := o.SaveAuthCode(ctx, a.ID, "code"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.AuthRequestByCode(ctx, "code"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.AuthRequestByCode(ctx, "code"); err == nil { // the replay
		t.Fatal("replay accepted")
	}
	if _, _, _, err := o.CreateAccessAndRefreshTokens(ctx, a, ""); !isInvalidGrant(err) {
		t.Fatalf("exchange after replay = %v", err)
	}
	if n := familyRows(t, s, a.Family); n != 0 {
		t.Fatalf("%d rows for a revoked family", n)
	}
}

func TestClientRevokedRacingTheExchangeLeavesNoGrant(t *testing.T) {
	ctx := context.Background()
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := redeem(t, o, "C")
	if err := s.RevokeClient("C"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := o.CreateAccessAndRefreshTokens(ctx, a, ""); !isInvalidGrant(err) {
		t.Fatalf("exchange after revocation = %v", err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants`) + count(t, s, `SELECT COUNT(*) FROM access_tokens`) + count(t, s, `SELECT COUNT(*) FROM refresh_tokens`); n != 0 {
		t.Fatalf("%d rows survived", n)
	}
}

// An exchange without a redeemed code (nothing in auth_codes for the
// family) must not create a grant either.
func TestExchangeWithoutRedeemedCodeIsRefused(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), a, ""); !isInvalidGrant(err) {
		t.Fatalf("err = %v", err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants`); n != 0 {
		t.Fatal("grant created without a code")
	}
}

func TestStorageErrorsToTheLibraryAreFixedText(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, refresh, _ := issue(t, o, "C")
	if _, err := s.db.Exec(`DROP TABLE refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	if _, err := o.TokenRequestByRefreshToken(context.Background(), refresh); !errors.Is(err, errStorage) {
		t.Fatalf("refresh lookup = %v", err)
	}
	if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), &refreshRequest{family: "f", clientID: "C"}, refresh); !errors.Is(err, errStorage) {
		t.Fatalf("rotate = %v", err)
	}
	if _, _, err := o.GetRefreshTokenInfo(context.Background(), "C", refresh); !errors.Is(err, errStorage) {
		t.Fatalf("info = %v", err)
	}
}

// A rotation that loses the race reports invalid_grant to the client.
func TestRacingRotationIsInvalidGrant(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, r1, _ := issue(t, o, "C")
	req1, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
	req2, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
	_, _, _, _ = o.CreateAccessAndRefreshTokens(context.Background(), req1, r1)
	_, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), req2, r1)
	var oe *oidc.Error
	if !errors.As(err, &oe) || oe.ErrorType != oidc.InvalidGrant {
		t.Fatalf("err = %v", err)
	}
}

func isInvalidGrant(err error) bool {
	var oe *oidc.Error
	return errors.As(err, &oe) && oe.ErrorType == oidc.InvalidGrant
}

func capture(o *opStorage) *bytes.Buffer {
	var buf bytes.Buffer
	o.logger = slog.New(slog.NewTextHandler(&buf, nil))
	return &buf
}

func TestReuseIsLoggedWithIdsOnly(t *testing.T) {
	for _, racing := range []bool{false, true} {
		o, s, _ := newTestOP(t)
		addClient(t, s, "C", "http://127.0.0.1/callback")
		_, r1, a := issue(t, o, "C")
		buf := capture(o)
		if racing {
			req1, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
			req2, _ := o.TokenRequestByRefreshToken(context.Background(), r1)
			_, _, _, _ = o.CreateAccessAndRefreshTokens(context.Background(), req1, r1)
			_, _, _, _ = o.CreateAccessAndRefreshTokens(context.Background(), req2, r1)
		} else {
			_, r2 := refreshOnce(t, o, r1)
			_ = r2
			_, _ = o.TokenRequestByRefreshToken(context.Background(), r1)
		}
		log := buf.String()
		if !strings.Contains(log, "refresh token reuse: grant revoked") || !strings.Contains(log, "client_id=C") || !strings.Contains(log, a.Family) {
			t.Fatalf("racing=%v log = %q", racing, log)
		}
		if strings.Contains(log, refreshPrefix) || strings.Contains(log, r1) {
			t.Fatal("a token appears in the log")
		}
	}
}

func TestGuardFailuresAreLogged(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	buf := capture(o)
	if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), a, ""); !isInvalidGrant(err) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(buf.String(), "code exchange refused") {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestExpiredTokensAreRefusedInTheirOwnQueries(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	id, r1, _ := issue(t, o, "C")
	req, err := o.TokenRequestByRefreshToken(context.Background(), r1)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(refreshTTL) // the refresh token expires after it was validated
	if _, _, _, err := o.CreateAccessAndRefreshTokens(context.Background(), req, r1); err == nil {
		t.Fatal("rotation of an expired refresh token succeeded")
	}
	// The access token row is still there (sweep has not run) but expired.
	if _, err := s.lookupAccess(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired access lookup = %v", err)
	}
}
