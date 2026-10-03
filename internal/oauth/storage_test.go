package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestOP(t *testing.T) (*opStorage, *Store, *testClock) {
	t.Helper()
	s, clk := newTestStore(t)
	sk, _, _, err := s.loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	a := defaultAllowlist(t)
	o := &opStorage{
		s: s, base: "https://cortex.example", mcpURL: "https://cortex.example/mcp", allow: a,
		resolver: newCIMDResolver(s, a, (&fakeFetch{err: errors.New("offline")}).fetch, discardLogger),
		signing:  sk, logger: discardLogger,
	}
	return o, s, clk
}

func withBrowser() context.Context {
	return context.WithValue(context.Background(), browserKey{}, "BROWSERHASH")
}

func addClient(t *testing.T, s *Store, id string, uris ...string) {
	t.Helper()
	if err := s.insertClient(clientRow{ID: id, Kind: kindDCR, Name: "Test " + id, RedirectURIs: uris, Created: s.now()}); err != nil {
		t.Fatal(err)
	}
}

// newApproved creates an auth request for client id the way /authorize and
// the login page would, and returns it approved.
func newApproved(t *testing.T, o *opStorage, clientID, redirect string) *authRequest {
	t.Helper()
	req, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{
		ClientID: clientID, RedirectURI: redirect, State: "st", Nonce: "n",
		CodeChallenge: s256("verifier-verifier-verifier-verifier-verifier"), CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		ResponseType: oidc.ResponseTypeCode, Scopes: oidc.SpaceDelimitedArray{"vault"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := o.s.completeAuthRequest(req.GetID(), "otp"); err != nil {
		t.Fatal(err)
	}
	a, err := o.s.authRequest(req.GetID())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestKeysAreCreatedOnceAndReused(t *testing.T) {
	s, _ := newTestStore(t)
	sk1, ck1, kid1, err := s.loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	sk2, ck2, kid2, err := s.loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if sk1.kid != sk2.kid || !sk1.priv.Equal(sk2.priv) || ck1 != ck2 || kid1 != kid2 || ck1 == [32]byte{} {
		t.Fatal("keys changed between loads")
	}
}

func TestKeySetPublishesTheSigningKey(t *testing.T) {
	o, _, _ := newTestOP(t)
	keys, err := o.KeySet(context.Background())
	if err != nil || len(keys) != 1 || keys[0].ID() != o.signing.kid || keys[0].Use() != "sig" {
		t.Fatalf("KeySet = %v, %v", keys, err)
	}
	if !keys[0].Key().(*ecdsa.PublicKey).Equal(&o.signing.priv.PublicKey) {
		t.Fatal("published key is not the signing key")
	}
}

func TestGetClientByClientID(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "WEB", "https://claude.ai/api/mcp/auth_callback")
	addClient(t, s, "NATIVE", "http://127.0.0.1/callback")
	addClient(t, s, "STALE", "https://removed.example/cb")
	c, err := o.GetClientByClientID(context.Background(), "WEB")
	if err != nil {
		t.Fatal(err)
	}
	if c.ApplicationType() != op.ApplicationTypeWeb || c.AuthMethod() != oidc.AuthMethodNone || !c.IsScopeAllowed("vault") || c.IsScopeAllowed("admin") ||
		len(c.ResponseTypes()) != 1 || c.ResponseTypes()[0] != oidc.ResponseTypeCode || len(c.GrantTypes()) != 2 ||
		c.LoginURL("a b") != "https://cortex.example/login?id=a+b" || c.AccessTokenType() != op.AccessTokenTypeBearer {
		t.Fatalf("web client = %+v", c)
	}
	if n, _ := o.GetClientByClientID(context.Background(), "NATIVE"); n.ApplicationType() != op.ApplicationTypeNative {
		t.Fatal("loopback client is not native")
	}
	// The allowlist is re-applied on every load: a removed entry disables
	// the client at once.
	if _, err := o.GetClientByClientID(context.Background(), "STALE"); err == nil {
		t.Fatal("client with no allowed redirect loaded")
	}
	if _, err := o.GetClientByClientID(context.Background(), "NOPE"); err == nil {
		t.Fatal("unknown client loaded")
	}
}

func TestGetClientResolvesMetadataDocuments(t *testing.T) {
	o, _, _ := newTestOP(t)
	f := &fakeFetch{}
	f.body.Store(cimdBody(testCIMD, "Doc App", "https://chatgpt.com/connector/oauth/abc"))
	o.resolver = newCIMDResolver(o.s, o.allow, f.fetch, discardLogger)
	c, err := o.GetClientByClientID(context.Background(), testCIMD)
	if err != nil || c.GetID() != testCIMD || c.RedirectURIs()[0] != "https://chatgpt.com/connector/oauth/abc" {
		t.Fatalf("CIMD client = %v, %v", c, err)
	}
}

func TestCreateAuthRequestRequiresS256(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	good := s256("verifier-verifier-verifier-verifier-verifier")
	for name, tc := range map[string]struct {
		challenge string
		method    oidc.CodeChallengeMethod
	}{
		"missing":      {"", ""},
		"plain":        {"verifier-verifier-verifier-verifier-verifier", oidc.CodeChallengeMethodPlain},
		"no method":    {good, ""},
		"short":        {good[:42], oidc.CodeChallengeMethodS256},
		"bad alphabet": {strings.Repeat("+", 43), oidc.CodeChallengeMethodS256},
	} {
		_, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "C", RedirectURI: "http://127.0.0.1/callback", CodeChallenge: tc.challenge, CodeChallengeMethod: tc.method}, "")
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.ErrorType != oidc.InvalidRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := count(t, s, `SELECT COUNT(*) FROM auth_requests`); n != 0 {
		t.Fatalf("%d requests stored", n)
	}
}

func TestCreateAuthRequestNeedsBrowserBinding(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	_, err := o.CreateAuthRequest(context.Background(), &oidc.AuthRequest{ClientID: "C", CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
	if err == nil {
		t.Fatal("request without a browser binding accepted")
	}
}

func TestAuthRequestLifecycle(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	req, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{
		ClientID: "C", RedirectURI: "http://127.0.0.1/callback", State: "xyz", Nonce: "n1",
		CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256, Scopes: oidc.SpaceDelimitedArray{"openid"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	a := req.(*authRequest)
	if len(a.ID) != 26 || len(a.CSRF) != 26 || a.Browser != "BROWSERHASH" || a.Done() || a.GetState() != "xyz" ||
		strings.Join(a.GetScopes(), " ") != "vault offline_access" || a.GetCodeChallenge().Method != oidc.CodeChallengeMethodS256 {
		t.Fatalf("created = %+v", a)
	}
	got, err := o.AuthRequestByID(context.Background(), a.ID)
	if err != nil || got.GetRedirectURI() != "http://127.0.0.1/callback" || got.GetNonce() != "n1" {
		t.Fatalf("AuthRequestByID = %+v, %v", got, err)
	}
	if err := s.completeAuthRequest(a.ID, "hwk"); err != nil {
		t.Fatal(err)
	}
	if err := s.completeAuthRequest(a.ID, "hwk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second approval = %v", err)
	}
	got, _ = o.AuthRequestByID(context.Background(), a.ID)
	if !got.Done() || got.GetAMR()[0] != "hwk" || got.GetAuthTime().IsZero() || got.GetSubject() != ownerSubject {
		t.Fatalf("approved = %+v", got)
	}
	clk.Advance(authRequestTTL)
	if _, err := o.AuthRequestByID(context.Background(), a.ID); err == nil {
		t.Fatal("expired request still loads")
	}
}

func TestCodeIsSingleUseAndReplayRevokesTheFamily(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	if err := o.SaveAuthCode(context.Background(), a.ID, "code-1"); err != nil {
		t.Fatal(err)
	}
	got, err := o.AuthRequestByCode(context.Background(), "code-1")
	if err != nil || got.GetID() != a.ID {
		t.Fatalf("first use = %v, %v", got, err)
	}
	insertGrant(t, s, a.Family, "C") // what the first exchange issued
	if _, err := o.AuthRequestByCode(context.Background(), "code-1"); err == nil {
		t.Fatal("code accepted twice")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM grants WHERE family = ?`, a.Family); n != 0 {
		t.Fatal("replaying a code did not revoke its family")
	}
}

func TestCodeExpiresAndNeedsApproval(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	pending, _ := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "C", RedirectURI: "http://127.0.0.1/callback", CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
	if err := o.SaveAuthCode(context.Background(), pending.GetID(), "early"); err == nil {
		t.Fatal("code saved for an unapproved request")
	}
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	_ = o.SaveAuthCode(context.Background(), a.ID, "code-2")
	clk.Advance(codeTTL)
	if _, err := o.AuthRequestByCode(context.Background(), "code-2"); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestSweepRemovesExpiredState(t *testing.T) {
	o, s, clk := newTestOP(t)
	addClient(t, s, "OLD", "http://127.0.0.1/callback")
	addClient(t, s, "USED", "http://127.0.0.1/callback")
	insertGrant(t, s, "F", "USED")
	_, _ = o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "OLD", RedirectURI: "http://127.0.0.1/callback", CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
	_, _ = s.Setup("h") // leaves an enrollment token
	clk.Advance(unusedClientTTL + time.Minute)
	s.lastSweep.Store(0)
	s.sweep()
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM auth_requests`:                   0,
		`SELECT COUNT(*) FROM enrollments`:                     0,
		`SELECT COUNT(*) FROM oauth_clients WHERE id = 'OLD'`:  0,
		`SELECT COUNT(*) FROM oauth_clients WHERE id = 'USED'`: 1,
	} {
		if n := count(t, s, q); n != want {
			t.Errorf("%s = %d, want %d", q, n, want)
		}
	}
}

// zitadel's native-client check accepts all of these for a client registered
// with http://127.0.0.1/callback; our allowlist must not.
func TestCreateAuthRequestRechecksTheAllowlist(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	for _, uri := range []string{
		"https://127.0.0.9/callback",
		"http://evil.com@127.0.0.1/callback",
		"http://[::ffff:127.0.0.1]/callback",
		"http://[0:0:0:0:0:0:0:1]/callback",
		"http://127.0.0.1/callback#x",
		"http://127.0.0.1/%63allback",
		"",
	} {
		_, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "C", RedirectURI: uri,
			CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
		var oe *oidc.Error
		if !errors.As(err, &oe) || !oe.IsRedirectDisabled() {
			t.Errorf("%q: err = %v, want an error that is not redirected to the URI", uri, err)
		}
	}
	if n := count(t, s, `SELECT COUNT(*) FROM auth_requests`); n != 0 {
		t.Fatalf("%d requests stored", n)
	}
	// A loopback URI on another port is still fine.
	if _, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "C", RedirectURI: "http://127.0.0.1:5000/callback",
		CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestCreateAuthRequestNeedsALiveClient(t *testing.T) {
	o, _, _ := newTestOP(t)
	_, err := o.CreateAuthRequest(withBrowser(), &oidc.AuthRequest{ClientID: "GONE", RedirectURI: "http://127.0.0.1/callback",
		CodeChallenge: s256("v"), CodeChallengeMethod: oidc.CodeChallengeMethodS256}, "")
	if err == nil {
		t.Fatal("request stored for a client that does not exist")
	}
	if n := count(t, o.s, `SELECT COUNT(*) FROM auth_requests`); n != 0 {
		t.Fatalf("%d requests stored", n)
	}
}

func TestSaveAuthCodeNeedsALiveClient(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	// A revocation that removed only the client row (the request survives).
	if _, err := s.db.Exec(`DELETE FROM oauth_clients WHERE id = 'C'`); err != nil {
		t.Fatal(err)
	}
	if err := o.SaveAuthCode(context.Background(), a.ID, "code-x"); err == nil {
		t.Fatal("code saved for a deleted client")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM auth_codes`); n != 0 {
		t.Fatalf("%d codes stored", n)
	}
}

func TestRevokedClientLosesItsRequests(t *testing.T) {
	o, s, _ := newTestOP(t)
	addClient(t, s, "C", "http://127.0.0.1/callback")
	a := newApproved(t, o, "C", "http://127.0.0.1/callback")
	_ = o.SaveAuthCode(context.Background(), a.ID, "code-y")
	if err := s.RevokeClient("C"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.AuthRequestByCode(context.Background(), "code-y"); err == nil {
		t.Fatal("code of a revoked client redeemed")
	}
}
