package oauth

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	recoveryCodeCount = 10
	// enrollTTL is how long a passkey enrollment link from setup works.
	enrollTTL       = 10 * time.Minute
	webauthnIDBytes = 64 // the maximum user handle; random, never shown
	totpSecretBytes = 20 // 160 bits, the RFC 4226 recommendation
	maxCodeBytes    = 64
)

var (
	errBadCode    = errors.New("code not accepted")
	errTOTPLocked = errors.New("authenticator codes are locked after too many failures")
	// errTOTPJustLocked is the bad code that reached maxTOTPFailures. It
	// wraps errBadCode; it is returned once per lock (the count only moves
	// from maxTOTPFailures-1 to maxTOTPFailures once until a reset), so the
	// caller can log the event once.
	errTOTPJustLocked = fmt.Errorf("%w; authenticator codes are now locked", errBadCode)
)

// SetupSecrets are shown once by cortex-mcp setup and never again.
type SetupSecrets struct {
	TOTPURI       string   // otpauth:// URI for an authenticator app
	TOTPSecret    string   // the same secret in base32, for manual entry
	RecoveryCodes []string // ten single-use codes, XXXX-XXXX-XXXX-XXXX
	EnrollToken   string   // one-time passkey enrollment token, valid enrollTTL
}

// Setup creates the owner: a passkey user handle, a TOTP secret, ten
// recovery codes, and a passkey enrollment token. It refuses to run twice;
// reset-auth starts over. host labels the entry in the authenticator app.
func (s *Store) Setup(host string) (SetupSecrets, error) {
	secret := randBytes(totpSecretBytes)
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
	}
	token := randToken()
	err := s.tx(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM owner`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadySetUp
		}
		if _, err := tx.Exec(`INSERT INTO owner(id, webauthn_id, totp_secret, created) VALUES(1, ?, ?, ?)`,
			randBytes(webauthnIDBytes), secret, s.unix()); err != nil {
			return err
		}
		for _, c := range codes {
			if _, err := tx.Exec(`INSERT INTO recovery_codes(hash) VALUES(?)`, hashToken(normalizeRecovery(c))); err != nil {
				return err
			}
		}
		return s.insertEnrollment(tx, token)
	})
	if err != nil {
		return SetupSecrets{}, err
	}
	return SetupSecrets{TOTPURI: otpauthURI(secret, host), TOTPSecret: base32NoPad(secret), RecoveryCodes: codes, EnrollToken: token}, nil
}

// NewEnrollment issues another passkey enrollment token for an existing
// owner (cortex-mcp setup -passkey).
func (s *Store) NewEnrollment() (string, error) {
	token := randToken()
	err := s.tx(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM owner`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNotSetUp
		}
		return s.insertEnrollment(tx, token)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) insertEnrollment(tx *sql.Tx, token string) error {
	_, err := tx.Exec(`INSERT INTO enrollments(hash, expires) VALUES(?, ?)`, hashToken(token), s.now().Add(enrollTTL).Unix())
	return err
}

// OwnerExists reports whether setup has run.
func (s *Store) OwnerExists() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM owner`).Scan(&n)
	return n > 0, err
}

// ResetAuth is the last resort when factors are lost or compromised: it
// deletes the owner's passkeys, TOTP secret, and recovery codes, and every
// OAuth client and grant, so anything connected with stolen factors is cut
// off too. Bearer tokens and the signing keys stay.
func (s *Store) ResetAuth() error {
	return s.tx(func(tx *sql.Tx) error {
		for _, table := range []string{
			"owner", "passkeys", "recovery_codes", "enrollments", "auth_requests", "auth_codes",
			"access_tokens", "refresh_tokens", "grants", "oauth_clients",
		} {
			// Table names are constants; DELETE cannot take them as parameters.
			if _, err := tx.Exec(`DELETE FROM ` + table); err != nil { // #nosec G202 -- constant table names
				return err
			}
		}
		return nil
	})
}

// verifyCode checks a code typed on the login page: six digits are a TOTP
// code, anything else is tried as a recovery code. It returns the method
// used, "otp" or "recovery".
func (s *Store) verifyCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > maxCodeBytes {
		return "", errBadCode
	}
	if isTOTPFormat(code) {
		return "otp", s.verifyTOTP(code)
	}
	return "recovery", s.useRecoveryCode(code)
}

// verifyTOTP accepts a current code once, counts failures, and refuses
// every code while the failure count is at maxTOTPFailures.
func (s *Store) verifyTOTP(code string) error {
	if !isTOTPFormat(code) {
		return errBadCode
	}
	return s.tx(func(tx *sql.Tx) error {
		var secret []byte
		var last, fails int64
		err := tx.QueryRow(`SELECT totp_secret, totp_last_step, totp_failures FROM owner WHERE id = 1`).Scan(&secret, &last, &fails)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotSetUp
		}
		if err != nil {
			return err
		}
		if fails >= maxTOTPFailures {
			return errTOTPLocked
		}
		step := matchTOTP(secret, code, s.now(), last)
		if step == 0 {
			if _, err := tx.Exec(`UPDATE owner SET totp_failures = totp_failures + 1 WHERE id = 1`); err != nil {
				return err
			}
			if fails+1 >= maxTOTPFailures {
				return keepErr{errTOTPJustLocked}
			}
			return keepErr{errBadCode}
		}
		_, err = tx.Exec(`UPDATE owner SET totp_last_step = ?, totp_failures = 0 WHERE id = 1`, step)
		return err
	})
}

// useRecoveryCode deletes the code's hash if present: deleting is what
// makes it single-use. A successful recovery login also unlocks TOTP.
func (s *Store) useRecoveryCode(code string) error {
	n := normalizeRecovery(code)
	if len(n) != 16 {
		return errBadCode
	}
	return s.tx(func(tx *sql.Tx) error {
		var owners int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM owner`).Scan(&owners); err != nil {
			return err
		}
		if owners == 0 {
			return ErrNotSetUp
		}
		res, err := tx.Exec(`DELETE FROM recovery_codes WHERE hash = ?`, hashToken(n))
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err != nil || rows != 1 {
			return errBadCode
		}
		_, err = tx.Exec(`UPDATE owner SET totp_failures = 0 WHERE id = 1`)
		return err
	})
}

func (s *Store) recoveryCodesLeft() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM recovery_codes`).Scan(&n)
	return n, err
}

// loginSucceeded clears the TOTP failure count after a passkey login.
func (s *Store) loginSucceeded() error {
	_, err := s.db.Exec(`UPDATE owner SET totp_failures = 0 WHERE id = 1`)
	return err
}

func (s *Store) enrollmentValid(token string) (bool, error) {
	if token == "" || len(token) > maxCodeBytes {
		return false, nil
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM enrollments WHERE hash = ? AND expires > ?`, hashToken(token), s.unix()).Scan(&n)
	return n > 0, err
}

// consumeEnrollment deletes an unexpired enrollment token, so a link works
// for one passkey ceremony only.
func (s *Store) consumeEnrollment(token string) error {
	res, err := s.db.Exec(`DELETE FROM enrollments WHERE hash = ? AND expires > ?`, hashToken(token), s.unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrNotFound
	}
	return nil
}

// newRecoveryCode is 16 base32 characters (80 bits) in four groups.
func newRecoveryCode() string {
	t := rand.Text()[:16]
	return t[0:4] + "-" + t[4:8] + "-" + t[8:12] + "-" + t[12:16]
}

// recoveryReplacer drops separators and maps the digits that are not in the
// base32 alphabet (A-Z, 2-7) to the letters they are mistaken for.
var recoveryReplacer = strings.NewReplacer("-", "", " ", "", "0", "O", "1", "I", "8", "B")

// normalizeRecovery accepts the code as typed: any case, with or without
// dashes and spaces, and with 0, 1 or 8 for O, I or B.
func normalizeRecovery(s string) string {
	return recoveryReplacer.Replace(strings.ToUpper(s))
}
