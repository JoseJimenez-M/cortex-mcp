package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/JoseJimenez-M/cortex-mcp/internal/authdb"
)

var b64u = base64.RawURLEncoding

// softKey is a software authenticator: enough of WebAuthn to register a
// P-256 credential with "none" attestation and sign assertions, so the real
// library verifies real signatures in these tests.
type softKey struct {
	priv   *ecdsa.PrivateKey
	id     []byte
	user   []byte
	rpID   string
	origin string
	count  uint32
	flags  byte // authenticator data flags; zero means user present and verified
}

func newSoftKey(t *testing.T, base string) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	return &softKey{priv: priv, id: randBytes(16), rpID: u.Hostname(), origin: base}
}

const flagsUPUV = byte(protocol.FlagUserPresent | protocol.FlagUserVerified)

func (k *softKey) userFlags() byte {
	if k.flags == 0 {
		return flagsUPUV
	}
	return k.flags
}

func (k *softKey) authData(flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	d := append([]byte{}, h[:]...)
	d = append(d, flags)
	d = binary.BigEndian.AppendUint32(d, k.count)
	return append(d, attested...)
}

func (k *softKey) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return b
}

// create answers navigator.credentials.create.
func (k *softKey) create(t *testing.T, challenge, userID string) []byte {
	t.Helper()
	user, err := b64u.DecodeString(userID)
	if err != nil {
		t.Fatal(err)
	}
	k.user = user
	pub, err := k.priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(map[int64]any{
		1: int64(webauthncose.EllipticKey), 3: int64(webauthncose.AlgES256), -1: int64(webauthncose.P256),
		-2: pub[1:33], -3: pub[33:65],
	})
	if err != nil {
		t.Fatal(err)
	}
	attested := make([]byte, 16) // AAGUID, all zero
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(k.id)))
	attested = append(attested, k.id...)
	attested = append(attested, cose...)
	att, err := webauthncbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{},
		"authData": k.authData(k.userFlags()|byte(protocol.FlagAttestedCredentialData), attested),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(k.id), "rawId": b64u.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(k.clientData("webauthn.create", challenge)),
			"attestationObject": b64u.EncodeToString(att),
		},
	})
	return body
}

// get answers navigator.credentials.get, signing with key (k.priv unless
// another key is given, to forge an assertion).
func (k *softKey) get(t *testing.T, challenge string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	if key == nil {
		key = k.priv
	}
	k.count++
	ad := k.authData(k.userFlags(), nil)
	cd := k.clientData("webauthn.get", challenge)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(k.id), "rawId": b64u.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig), "userHandle": b64u.EncodeToString(k.user),
		},
	})
	return body
}

func postJSON(t *testing.T, c *http.Client, u string, body []byte) (int, map[string]any) {
	t.Helper()
	status, out, _ := postJSONWith(t, c, u, body, nil)
	return status, out
}

// postJSONWith posts body with extra headers.
func postJSONWith(t *testing.T, c *http.Client, u string, body []byte, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeJSON(t, resp), resp.Header
}

// enrollBegin starts a registration ceremony with a fresh TOTP code.
func (e *testEnv) enrollBegin(t *testing.T, token string) map[string]any {
	t.Helper()
	in, _ := json.Marshal(map[string]string{"token": token, "code": e.totpNow(t)})
	status, out := postJSON(t, http.DefaultClient, e.url+"/enroll/begin", in)
	if status != http.StatusOK {
		t.Fatalf("enroll begin: %d %v", status, out)
	}
	return out
}

// enrollFinish answers a begun ceremony with k.
func (e *testEnv) enrollFinish(t *testing.T, k *softKey, begun map[string]any) (int, map[string]any) {
	t.Helper()
	pk := begun["options"].(map[string]any)["publicKey"].(map[string]any)
	body := k.create(t, pk["challenge"].(string), pk["user"].(map[string]any)["id"].(string))
	status, out, _ := postJSONWith(t, http.DefaultClient, e.url+"/enroll/finish", body, map[string]string{enrollSessionHeader: begun["session"].(string)})
	return status, out
}

// enroll registers k for the owner through the enrollment page's API.
func (e *testEnv) enroll(t *testing.T, k *softKey, token string) {
	t.Helper()
	if status, out := e.enrollFinish(t, k, e.enrollBegin(t, token)); status != http.StatusOK {
		t.Fatalf("enroll finish: %d %v", status, out)
	}
}

// passkeyBegin asks for login options; the CSRF token travels in a header,
// never in the URL.
func (e *testEnv) passkeyBegin(t *testing.T, id, csrf string) (int, map[string]any, http.Header) {
	t.Helper()
	return postJSONWith(t, e.browser, e.url+"/login/passkey/begin?id="+url.QueryEscape(id), nil, map[string]string{csrfHeader: csrf})
}

func (e *testEnv) passkeyFinish(t *testing.T, id, csrf string, body []byte) (int, map[string]any) {
	t.Helper()
	status, out, _ := postJSONWith(t, e.browser, e.url+"/login/passkey/finish?id="+url.QueryEscape(id), body, map[string]string{csrfHeader: csrf})
	return status, out
}

// passkeyLogin runs the login page's passkey flow for auth request id.
func (e *testEnv) passkeyLogin(t *testing.T, k *softKey, id, csrf string, key *ecdsa.PrivateKey) (int, map[string]any) {
	t.Helper()
	status, out, _ := e.passkeyBegin(t, id, csrf)
	if status != http.StatusOK {
		return status, out
	}
	challenge := out["publicKey"].(map[string]any)["challenge"].(string)
	return e.passkeyFinish(t, id, csrf, k.get(t, challenge, key))
}

// pendingPasskeyLogin starts an authorization and returns its id and CSRF.
func (e *testEnv) pendingPasskeyLogin(t *testing.T, clientID string) (string, string) {
	t.Helper()
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, newPKCE(), nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	return id, csrfOf(t, body)
}

func TestEnrollAndLoginWithPasskey(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	resp, err := http.Get(e.url + "/enroll")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "Register a passkey") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("enroll page: %d %s", resp.StatusCode, page)
	}
	pageHeadersOK(t, "enroll page", resp.Header)
	if inlineHandlerRE.Match(page) {
		t.Fatalf("inline handler on the enroll page:\n%s", page)
	}
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	if n, _ := e.svc.store.passkeyCount(); n != 1 {
		t.Fatalf("%d passkeys", n)
	}

	clientID := e.register(t, loopbackRedirect)
	p := newPKCE()
	id := e.startAuthorize(t, e.browser, e.authorizeURL(clientID, loopbackRedirect, p, nil))
	_, body, _ := e.loginPage(t, e.browser, id)
	if !strings.Contains(body, "Approve with passkey") {
		t.Fatal("no passkey button once a passkey exists")
	}
	status, out := e.passkeyLogin(t, k, id, csrfOf(t, body), nil)
	if status != http.StatusOK || out["redirect"] != e.svc.callbackURL(id) {
		t.Fatalf("passkey login: %d %v", status, out)
	}
	code := e.callback(t, e.browser, id).Query().Get("code")
	if status, tok := e.exchange(t, clientID, code, loopbackRedirect, p.verifier, nil); status != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("exchange: %d %v", status, tok)
	}
	// The stored credential carries the counter of the last login.
	owner, err := e.svc.store.ownerUser()
	if err != nil || len(owner.creds) != 1 || owner.creds[0].Authenticator.SignCount != k.count {
		t.Fatalf("stored credential after login: %v %+v", err, owner)
	}
}

func TestEnrollmentRefusals(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	wrong := wrongTOTP(ownerSecret(t, e.svc.store), e.clock.Now())
	for name, in := range map[string]map[string]string{
		"wrong code":    {"token": sec.EnrollToken, "code": wrong},
		"recovery code": {"token": sec.EnrollToken, "code": sec.RecoveryCodes[0]},
		"forged token":  {"token": "forged", "code": "123456"},
	} {
		b, _ := json.Marshal(in)
		if status, _ := postJSON(t, http.DefaultClient, e.url+"/enroll/begin", b); status != http.StatusUnauthorized && status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
	}
	if ok, _ := e.svc.store.enrollmentValid(sec.EnrollToken); !ok {
		t.Fatal("a refused attempt consumed the enrollment token")
	}
	if n, _ := e.svc.store.recoveryCodesLeft(); n != 10 {
		t.Fatal("the enrollment page consumed a recovery code")
	}
	e.enroll(t, newSoftKey(t, e.url), sec.EnrollToken)
	b, _ := json.Marshal(map[string]string{"token": sec.EnrollToken, "code": e.totpNow(t)})
	if status, _ := postJSON(t, http.DefaultClient, e.url+"/enroll/begin", b); status != http.StatusBadRequest {
		t.Fatalf("reused token: %d", status)
	}
	if status, _, _ := postJSONWith(t, http.DefaultClient, e.url+"/enroll/finish", []byte(`{}`), map[string]string{enrollSessionHeader: "nope"}); status != http.StatusBadRequest {
		t.Fatalf("finish without begin: %d", status)
	}
}

// The registration ceremony key is read from the header only, never from
// the URL.
func TestEnrollSessionKeyIsNeverReadFromTheURL(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	begun := e.enrollBegin(t, sec.EnrollToken)
	k := newSoftKey(t, e.url)
	pk := begun["options"].(map[string]any)["publicKey"].(map[string]any)
	body := k.create(t, pk["challenge"].(string), pk["user"].(map[string]any)["id"].(string))
	if status, _ := postJSON(t, http.DefaultClient, e.url+"/enroll/finish?session="+url.QueryEscape(begun["session"].(string)), body); status != http.StatusBadRequest {
		t.Fatalf("finish with the session key in the query: %d", status)
	}
	if n, _ := e.svc.store.passkeyCount(); n != 0 {
		t.Fatal("a passkey was stored from a query-string session key")
	}
}

// Requirement: the enrollment link is gated by the atomic consume (a
// single-use DELETE), never by a validity check followed by a later
// consume. Ceremonies started in parallel from one link (both past the
// TOTP check) yield exactly one session and so exactly one credential.
func TestEnrollmentLinkIsSingleUseUnderRace(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	const n = 8
	type started struct {
		key     string
		options *protocol.CredentialCreation
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins []started
		errs []error
	)
	gate := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-gate
			key, opts, err := e.svc.passkeys.startEnrollment(sec.EnrollToken)
			if err == nil {
				mu.Lock()
				wins = append(wins, started{key, opts})
				mu.Unlock()
			} else if !errors.Is(err, ErrNotFound) {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		})
	}
	close(gate)
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("startEnrollment: %v", errs)
	}
	if len(wins) != 1 {
		t.Fatalf("%d ceremonies started from one enrollment link, want 1", len(wins))
	}
	// Answer the winning ceremony with two authenticators at once: the
	// session is single use, so only one credential can land.
	raw, _ := json.Marshal(wins[0].options)
	var opts map[string]any
	_ = json.Unmarshal(raw, &opts)
	pk := opts["publicKey"].(map[string]any)
	var bodies [2][]byte
	for i := range bodies {
		bodies[i] = newSoftKey(t, e.url).create(t, pk["challenge"].(string), pk["user"].(map[string]any)["id"].(string))
	}
	var codes [2]int
	for i := range codes {
		wg.Go(func() {
			req, err := http.NewRequest(http.MethodPost, e.url+"/enroll/finish", strings.NewReader(string(bodies[i])))
			if err != nil {
				return
			}
			req.Header.Set(enrollSessionHeader, wins[0].key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		})
	}
	wg.Wait()
	if got, _ := e.svc.store.passkeyCount(); got != 1 || codes[0]+codes[1] != http.StatusOK+http.StatusBadRequest {
		t.Fatalf("%d passkeys stored, finish statuses %v; want exactly one", got, codes)
	}
}

func TestPasskeyLoginRefusals(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	clientID := e.register(t, loopbackRedirect)
	id, csrf := e.pendingPasskeyLogin(t, clientID)
	k := newSoftKey(t, e.url)
	if status, _ := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusBadRequest {
		t.Fatalf("passkey login with no passkey registered: %d", status)
	}
	e.enroll(t, k, sec.EnrollToken)
	if status, _ := e.passkeyLogin(t, k, id, "wrong", nil); status != http.StatusBadRequest {
		t.Fatalf("wrong csrf: %d", status)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if status, _ := e.passkeyLogin(t, k, id, csrf, other); status != http.StatusUnauthorized {
		t.Fatalf("forged signature: %d", status)
	}
	if status, _ := e.passkeyFinish(t, id, csrf, k.get(t, "x", nil)); status != http.StatusBadRequest {
		t.Fatalf("finish without begin: %d", status)
	}
	if status, _ := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusOK {
		t.Fatalf("genuine login after refusals: %d", status)
	}
	// A counter that does not grow means a cloned authenticator.
	id2, csrf2 := e.pendingPasskeyLogin(t, clientID)
	k.count--
	if status, _ := e.passkeyLogin(t, k, id2, csrf2, nil); status != http.StatusUnauthorized {
		t.Fatalf("cloned counter: %d", status)
	}
}

// A non-zero counter that goes backwards is refused, logged, and the stored
// counter is not moved back.
func TestPasskeyCloneIsRefusedAndLogged(t *testing.T) {
	logs := &recordHandler{}
	e := newTestEnvWith(t, func(o *Options) { o.Logger = slog.New(logs) })
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	clientID := e.register(t, loopbackRedirect)
	id, csrf := e.pendingPasskeyLogin(t, clientID)
	k.count = 9
	if status, out := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusOK {
		t.Fatalf("login at counter 10: %d %v", status, out)
	}
	id, csrf = e.pendingPasskeyLogin(t, clientID)
	k.count = 3
	if status, _ := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusUnauthorized {
		t.Fatalf("login at counter 4 after 10: %d", status)
	}
	owner, err := e.svc.store.ownerUser()
	if err != nil || owner.creds[0].Authenticator.SignCount != 10 || owner.creds[0].Authenticator.CloneWarning {
		t.Fatalf("stored credential after a clone signal: %v %+v", err, owner.creds)
	}
	warned := false
	for _, l := range logs.text() {
		if strings.HasPrefix(l, "WARN") && strings.Contains(l, "cloned") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no clone warning logged: %q", logs.text())
	}
}

// The CSRF token is accepted only in the header: a token in the query
// string (where proxies and browser history keep it) is not read.
func TestPasskeyCSRFTokenIsNeverReadFromTheURL(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	e.enroll(t, newSoftKey(t, e.url), sec.EnrollToken)
	id, csrf := e.pendingPasskeyLogin(t, e.register(t, loopbackRedirect))
	q := "?" + url.Values{"id": {id}, "csrf": {csrf}}.Encode()
	for _, path := range []string{"/login/passkey/begin", "/login/passkey/finish"} {
		if status, _ := postJSON(t, e.browser, e.url+path+q, []byte(`{}`)); status != http.StatusBadRequest {
			t.Fatalf("%s with the CSRF token in the query: %d", path, status)
		}
	}
	js := string(passkeyLoginJS)
	if !strings.Contains(js, csrfHeader) || strings.Contains(js, "csrf:") || strings.Contains(js, "URLSearchParams") {
		t.Fatalf("the login page script must send the CSRF token in the %s header only:\n%s", csrfHeader, js)
	}
}

// Passkey logins charge the same per-source then global limiter as codes:
// attempts on /login and passkey ceremonies draw on one budget.
func TestPasskeyLoginSharesTheLoginRateLimit(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	e.enroll(t, newSoftKey(t, e.url), sec.EnrollToken) // one attempt
	form := e.pendingLogin(t)
	for i := 1; i < loginPerIPBurst; i++ {
		if status, _, _ := postPage(t, e.browser, e.url+"/login", form); status != http.StatusUnauthorized {
			t.Fatalf("code attempt %d: %d", i, status)
		}
	}
	status, out, h := e.passkeyBegin(t, form.Get("id"), form.Get("csrf"))
	if status != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("passkey begin past the per-source burst: %d %v", status, out)
	}
	in, _ := json.Marshal(map[string]string{"token": "any", "code": "123456"})
	if status, _ := postJSON(t, http.DefaultClient, e.url+"/enroll/begin", in); status != http.StatusTooManyRequests {
		t.Fatalf("enroll begin past the per-source burst: %d", status)
	}
}

// A passkey proves possession of a stronger factor, so it clears the TOTP
// lock.
func TestPasskeyLoginClearsTheTOTPLock(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	if _, err := e.svc.store.db.Exec(`UPDATE owner SET totp_failures = ?`, maxTOTPFailures); err != nil {
		t.Fatal(err)
	}
	clientID := e.register(t, loopbackRedirect)
	id, csrf := e.pendingPasskeyLogin(t, clientID)
	if status, out := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusOK {
		t.Fatalf("passkey login while TOTP is locked: %d %v", status, out)
	}
	var fails int
	if err := e.svc.store.db.QueryRow(`SELECT totp_failures FROM owner`).Scan(&fails); err != nil || fails != 0 {
		t.Fatalf("totp_failures after a passkey login = %d, %v", fails, err)
	}
	e.loginWithTOTP(t, e.browser, clientID, newPKCE())
}

// Registration and login demand user verification and a discoverable
// credential; an authenticator that only proves presence is refused.
func TestPasskeysRequireUserVerification(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	begun := e.enrollBegin(t, sec.EnrollToken)
	sel := begun["options"].(map[string]any)["publicKey"].(map[string]any)["authenticatorSelection"].(map[string]any)
	if sel["userVerification"] != "required" || sel["residentKey"] != "required" || sel["requireResidentKey"] != true {
		t.Fatalf("registration authenticatorSelection = %v", sel)
	}
	presenceOnly := newSoftKey(t, e.url)
	presenceOnly.flags = byte(protocol.FlagUserPresent)
	if status, _ := e.enrollFinish(t, presenceOnly, begun); status != http.StatusBadRequest {
		t.Fatalf("registration without user verification: %d", status)
	}
	if n, _ := e.svc.store.passkeyCount(); n != 0 {
		t.Fatal("a credential without user verification was stored")
	}
	token, err := e.svc.store.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	k := newSoftKey(t, e.url)
	e.enroll(t, k, token)
	id, csrf := e.pendingPasskeyLogin(t, e.register(t, loopbackRedirect))
	status, out, _ := e.passkeyBegin(t, id, csrf)
	if status != http.StatusOK || out["publicKey"].(map[string]any)["userVerification"] != "required" {
		t.Fatalf("login options: %d %v", status, out)
	}
	k.flags = byte(protocol.FlagUserPresent)
	challenge := out["publicKey"].(map[string]any)["challenge"].(string)
	if status, _ := e.passkeyFinish(t, id, csrf, k.get(t, challenge, nil)); status != http.StatusUnauthorized {
		t.Fatalf("login without user verification: %d", status)
	}
}

// The origin in the client data must be public_url's origin exactly.
func TestPasskeyOriginMustMatchExactly(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	clientID := e.register(t, loopbackRedirect)
	u, _ := url.Parse(e.url)
	for _, origin := range []string{
		"https://" + u.Host,                    // other scheme
		"http://localhost:1",                   // other port
		"http://evil.localhost:" + u.Port(),    // subdomain
		"http://localhost:" + u.Port() + ".ev", // suffix
	} {
		id, csrf := e.pendingPasskeyLogin(t, clientID)
		k.origin = origin
		if status, _ := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusUnauthorized {
			t.Fatalf("origin %s: %d", origin, status)
		}
	}
}

func TestPasskeysDisabledForAnIPPublicURL(t *testing.T) {
	db, err := authdb.Open(filepath.Join(t.TempDir(), "s", "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	logs := &recordHandler{}
	svc, err := New(Options{DB: db, PublicURL: "http://127.0.0.1:8080", RedirectAllowlist: []string{"loopback"}, Logger: slog.New(logs),
		fetch: (&fakeFetch{err: errors.New("offline")}).fetch})
	if err != nil {
		t.Fatalf("New with an IP public URL: %v", err)
	}
	mux := http.NewServeMux()
	svc.Register(mux)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/enroll", nil),
		httptest.NewRequest(http.MethodPost, "/enroll/begin", nil),
		httptest.NewRequest(http.MethodPost, "/login/passkey/begin", nil),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s with passkeys disabled: %d", r.Method, r.URL.Path, rec.Code)
		}
	}
	warned := false
	for _, l := range logs.text() {
		if strings.HasPrefix(l, "WARN") && strings.Contains(l, "passkeys are disabled") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no startup warning: %q", logs.text())
	}
}

// With passkeys disabled, the login page never offers the passkey button,
// even if a passkey row exists from an earlier configuration.
func TestLoginPageHidesPasskeysWhenDisabled(t *testing.T) {
	var ipURL string
	e := newTestEnvWith(t, func(o *Options) {
		ipURL = strings.Replace(strings.TrimSuffix(o.PublicURL, "/"), "localhost", "127.0.0.1", 1)
		o.PublicURL = ipURL
	})
	e.url = ipURL
	e.setupOwner(t)
	if _, err := e.svc.store.db.Exec(`INSERT INTO passkeys(id, credential, created) VALUES(x'01', x'7b7d', 1)`); err != nil {
		t.Fatal(err)
	}
	id := e.startAuthorize(t, e.browser, e.authorizeURL(e.register(t, loopbackRedirect), loopbackRedirect, newPKCE(), nil))
	status, body, _ := e.loginPage(t, e.browser, id)
	if status != http.StatusOK || strings.Contains(body, "Approve with passkey") || strings.Contains(body, "<script") {
		t.Fatalf("login page with passkeys disabled: %d\n%s", status, body)
	}
}

func TestCeremonies(t *testing.T) {
	clk := newTestClock()
	c := newCeremonies(clk.Now)
	d := &webauthn.SessionData{Challenge: "c1"}
	if !c.put("a", d) {
		t.Fatal("put refused on an empty store")
	}
	if got, ok := c.take("a"); !ok || got.Challenge != "c1" {
		t.Fatalf("take = %v %v", got, ok)
	}
	if _, ok := c.take("a"); ok {
		t.Fatal("a challenge was answered twice")
	}

	c.put("old", d)
	clk.Advance(ceremonyTTL)
	if _, ok := c.take("old"); ok {
		t.Fatal("an expired ceremony was returned")
	}

	for i := range maxCeremonies {
		if !c.put(string(rune('A'+i)), d) {
			t.Fatalf("put %d refused below the cap", i)
		}
	}
	if c.put("one-too-many", d) {
		t.Fatal("put accepted past maxCeremonies")
	}
	// Restarting a ceremony under the same key replaces it, even at the cap.
	if !c.put("A", &webauthn.SessionData{Challenge: "c2"}) {
		t.Fatal("replacing a ceremony at the cap was refused")
	}
	if got, _ := c.take("A"); got.Challenge != "c2" {
		t.Fatalf("replaced ceremony = %v", got)
	}
	// Expired ceremonies free their slots.
	clk.Advance(ceremonyTTL + time.Second)
	if !c.put("fresh", d) {
		t.Fatal("expired ceremonies still count against the cap")
	}
}

// An assertion answers the challenge of the auth request it was begun for:
// posted to another pending request's finish it is refused and neither
// request is approved.
func TestPasskeyAssertionIsBoundToItsAuthRequest(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	clientID := e.register(t, loopbackRedirect)
	idA, csrfA := e.pendingPasskeyLogin(t, clientID)
	idB, csrfB := e.pendingPasskeyLogin(t, clientID)
	_, outA, _ := e.passkeyBegin(t, idA, csrfA)
	if status, out, _ := e.passkeyBegin(t, idB, csrfB); status != http.StatusOK {
		t.Fatalf("begin B: %d %v", status, out)
	}
	assertionA := k.get(t, outA["publicKey"].(map[string]any)["challenge"].(string), nil)
	if status, _ := e.passkeyFinish(t, idB, csrfB, assertionA); status != http.StatusUnauthorized {
		t.Fatalf("A's assertion on B's finish: %d", status)
	}
	if status, _ := e.passkeyFinish(t, idB, csrfA, assertionA); status != http.StatusBadRequest {
		t.Fatalf("A's assertion with A's CSRF on B's finish: %d", status)
	}
	for _, id := range []string{idA, idB} {
		if a, err := e.svc.store.authRequest(id); err != nil || a.IsDone {
			t.Fatalf("auth request %s after a cross-request assertion: %v %+v", id, err, a)
		}
	}
}

// The user handle in an assertion must be the owner's.
func TestPasskeyForeignUserHandleIsRefused(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	k.user = randBytes(64)
	id, csrf := e.pendingPasskeyLogin(t, e.register(t, loopbackRedirect))
	if status, _ := e.passkeyLogin(t, k, id, csrf, nil); status != http.StatusUnauthorized {
		t.Fatalf("foreign user handle: %d", status)
	}
}

// The login limiter's budget over one ceremony lifetime stays below the
// ceremony cap, so admitted begins alone can never fill the map.
func TestCeremonyCapExceedsTheLoginBudget(t *testing.T) {
	if budget := loginGlobalBurst + int(ceremonyTTL/loginGlobalEvery); budget >= maxCeremonies {
		t.Fatalf("login budget per ceremonyTTL = %d, maxCeremonies = %d", budget, maxCeremonies)
	}
}

// The stored sign count only moves forward (both zero is allowed), so two
// logins racing on one counter value cannot both be recorded.
func TestUpdatePasskeyOnlyMovesTheCounterForward(t *testing.T) {
	s, _ := newTestStore(t)
	c := &webauthn.Credential{ID: []byte{1}, Authenticator: webauthn.Authenticator{SignCount: 5}}
	if err := s.addPasskey(c); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		count uint32
		want  error
	}{{6, nil}, {6, errCounterNotIncreased}, {4, errCounterNotIncreased}, {7, nil}} {
		c.Authenticator.SignCount = step.count
		if err := s.updatePasskey(c); !errors.Is(err, step.want) {
			t.Fatalf("update to %d: %v, want %v", step.count, err, step.want)
		}
	}
	z := &webauthn.Credential{ID: []byte{2}}
	if err := s.addPasskey(z); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := s.updatePasskey(z); err != nil {
			t.Fatalf("zero counter update %d: %v", i, err)
		}
	}
}

func TestFinishEnrollStorageErrors(t *testing.T) {
	e := newTestEnv(t)
	sec := e.setupOwner(t)
	k := newSoftKey(t, e.url)
	e.enroll(t, k, sec.EnrollToken)
	// The same authenticator again: a conflict, not a server error.
	token, err := e.svc.store.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if status, out := e.enrollFinish(t, k, e.enrollBegin(t, token)); status != http.StatusConflict {
		t.Fatalf("registering the same passkey twice: %d %v", status, out)
	}
	// Any other storage failure is a 500 with fixed text.
	if _, err := e.svc.store.db.Exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON passkeys BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	token, _ = e.svc.store.NewEnrollment()
	status, out := e.enrollFinish(t, newSoftKey(t, e.url), e.enrollBegin(t, token))
	if status != http.StatusInternalServerError || strings.Contains(fmt.Sprint(out), "fire") {
		t.Fatalf("storage failure: %d %v", status, out)
	}
}

func TestPasskeyMessages(t *testing.T) {
	login, enroll := string(passkeyLoginJS), string(enrollJS)
	if !strings.Contains(login, "429") || !strings.Contains(login, "Too many attempts. Wait a minute") {
		t.Fatal("the login script does not explain a 429")
	}
	if strings.Contains(enroll, "e.message") || !strings.Contains(enroll, "429") {
		t.Fatal("the enroll script may show a raw exception message or does not explain a 429")
	}
	// A body that fails to read for a reason other than size gets fixed text.
	rec := httptest.NewRecorder()
	if _, ok := readBody(rec, httptest.NewRequest(http.MethodPost, "/", iotest.ErrReader(errors.New("secret detail"))), 10); ok ||
		!strings.Contains(rec.Body.String(), "could not be read") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("read error answer: %v %s", ok, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if _, ok := readBody(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 11))), 10); ok || !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("oversized body answer: %s", rec.Body.String())
	}
}
