package oauth

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var recoveryRE = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`)

func TestSetupOnce(t *testing.T) {
	s, _ := newTestStore(t)
	if ok, err := s.OwnerExists(); err != nil || ok {
		t.Fatalf("OwnerExists before setup = %v, %v", ok, err)
	}
	sec, err := s.Setup("cortex.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sec.TOTPURI, "otpauth://totp/") || len(sec.TOTPSecret) != 32 || len(sec.EnrollToken) != 43 {
		t.Fatalf("secrets = %+v", sec)
	}
	seen := map[string]bool{}
	for _, c := range sec.RecoveryCodes {
		if !recoveryRE.MatchString(c) || seen[c] {
			t.Fatalf("recovery code %q malformed or repeated", c)
		}
		seen[c] = true
	}
	if len(seen) != 10 {
		t.Fatalf("%d recovery codes", len(seen))
	}
	if ok, _ := s.OwnerExists(); !ok {
		t.Fatal("owner missing after setup")
	}
	if _, err := s.Setup("cortex.example.com"); !errors.Is(err, ErrAlreadySetUp) {
		t.Fatalf("second Setup = %v", err)
	}
}

func TestTOTPLoginIsSingleUse(t *testing.T) {
	s, clk := newTestStore(t)
	if _, err := s.Setup("h"); err != nil {
		t.Fatal(err)
	}
	secret := ownerSecret(t, s)
	code := hotp(secret, uint64(totpStep(clk.Now())), totpDigits)
	if m, err := s.verifyCode(code); err != nil || m != "otp" {
		t.Fatalf("verifyCode = %q, %v", m, err)
	}
	if _, err := s.verifyCode(code); !errors.Is(err, errBadCode) {
		t.Fatalf("replay = %v", err)
	}
	prev := hotp(secret, uint64(totpStep(clk.Now())-1), totpDigits)
	if _, err := s.verifyCode(prev); !errors.Is(err, errBadCode) {
		t.Fatalf("older step after a newer one = %v", err)
	}
	clk.Advance(30 * time.Second)
	if _, err := s.verifyCode(hotp(secret, uint64(totpStep(clk.Now())), totpDigits)); err != nil {
		t.Fatalf("next step = %v", err)
	}
}

func TestTOTPLocksAfterFailuresAndRecoveryUnlocks(t *testing.T) {
	s, clk := newTestStore(t)
	sec, _ := s.Setup("h")
	secret := ownerSecret(t, s)
	for i := 0; i < maxTOTPFailures; i++ {
		if _, err := s.verifyCode(wrongTOTP(secret, clk.Now())); !errors.Is(err, errBadCode) {
			t.Fatalf("attempt %d = %v", i, err)
		}
	}
	good := hotp(secret, uint64(totpStep(clk.Now())), totpDigits)
	if _, err := s.verifyCode(good); !errors.Is(err, errTOTPLocked) {
		t.Fatalf("after %d failures = %v", maxTOTPFailures, err)
	}
	if m, err := s.verifyCode(strings.ToLower(sec.RecoveryCodes[0])); err != nil || m != "recovery" {
		t.Fatalf("recovery code = %q, %v", m, err)
	}
	if _, err := s.verifyCode(good); err != nil {
		t.Fatalf("TOTP after a recovery login = %v", err)
	}
}

func TestLoginSucceededResetsFailures(t *testing.T) {
	s, clk := newTestStore(t)
	_, _ = s.Setup("h")
	secret := ownerSecret(t, s)
	for i := 0; i < maxTOTPFailures; i++ {
		_, _ = s.verifyCode(wrongTOTP(secret, clk.Now()))
	}
	if err := s.loginSucceeded(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.verifyCode(hotp(secret, uint64(totpStep(clk.Now())), totpDigits)); err != nil {
		t.Fatalf("TOTP after a passkey login = %v", err)
	}
}

func TestRecoveryCodesAreSingleUseAndForgiving(t *testing.T) {
	s, _ := newTestStore(t)
	sec, _ := s.Setup("h")
	spaced := strings.ReplaceAll(strings.ToLower(sec.RecoveryCodes[1]), "-", " ")
	if _, err := s.verifyCode(spaced); err != nil {
		t.Fatalf("lowercase, spaced code = %v", err)
	}
	if _, err := s.verifyCode(sec.RecoveryCodes[1]); !errors.Is(err, errBadCode) {
		t.Fatalf("second use = %v", err)
	}
	if n, err := s.recoveryCodesLeft(); err != nil || n != 9 {
		t.Fatalf("left = %d, %v", n, err)
	}
	for _, bad := range []string{"", "AAAA-AAAA-AAAA-AAAA", "nope", strings.Repeat("A", 200)} {
		if _, err := s.verifyCode(bad); !errors.Is(err, errBadCode) {
			t.Errorf("%q = %v", bad, err)
		}
	}
}

func TestCodesNeedAnOwner(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.verifyCode("123456"); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("TOTP without owner = %v", err)
	}
	if _, err := s.verifyCode("AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("recovery without owner = %v", err)
	}
	if _, err := s.NewEnrollment(); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("NewEnrollment without owner = %v", err)
	}
}

func TestEnrollmentTokens(t *testing.T) {
	s, clk := newTestStore(t)
	sec, _ := s.Setup("h")
	if ok, err := s.enrollmentValid(sec.EnrollToken); err != nil || !ok {
		t.Fatalf("fresh token = %v, %v", ok, err)
	}
	if ok, _ := s.enrollmentValid("forged"); ok {
		t.Fatal("unknown token valid")
	}
	if err := s.consumeEnrollment(sec.EnrollToken); err != nil {
		t.Fatal(err)
	}
	if err := s.consumeEnrollment(sec.EnrollToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume = %v", err)
	}
	tok, err := s.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(enrollTTL + time.Second)
	if ok, _ := s.enrollmentValid(tok); ok {
		t.Fatal("expired token valid")
	}
	if err := s.consumeEnrollment(tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consume expired = %v", err)
	}
}

func TestResetAuthClearsOwnerAndOAuthButKeepsTokensAndKeys(t *testing.T) {
	s, _ := newTestStore(t)
	_, _ = s.Setup("h")
	for _, stmt := range []string{
		`INSERT INTO oauth_clients(id, kind, name, redirect_uris, created) VALUES('C', 'dcr', 'n', '[]', 1)`,
		`INSERT INTO grants(family, client_id, scopes, audience, amr, auth_time, created, last_used) VALUES('F', 'C', 'vault', 'x', 'otp', 1, 1, 1)`,
		`INSERT INTO oauth_keys(name, kid, material) VALUES('crypto', 'k', x'00')`,
		`INSERT INTO bearer_tokens(name, hash, created, id) VALUES('cli', x'01', 1, 'I')`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ResetAuth(); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{
		"owner": 0, "passkeys": 0, "recovery_codes": 0, "enrollments": 0, "oauth_clients": 0, "grants": 0,
		"oauth_keys": 1, "bearer_tokens": 1,
	} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != want {
			t.Errorf("%s: %d rows, %v; want %d", table, n, err, want)
		}
	}
	if _, err := s.Setup("h"); err != nil {
		t.Fatalf("Setup after reset = %v", err)
	}
}
