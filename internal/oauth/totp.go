package oauth

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is HMAC-SHA1; authenticator apps support nothing else
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	totpPeriod = 30 // seconds per step (RFC 6238 default)
	totpDigits = 6
	// totpSkew accepts one step either side, for clock drift between the
	// phone and the server.
	totpSkew = 1
	// maxTOTPFailures locks the TOTP factor after this many consecutive bad
	// codes. With 3 valid codes in 10^6, 50 guesses succeed with 0.015%
	// probability in total; the owner unlocks with a passkey or recovery code.
	maxTOTPFailures = 50
)

// hotp is RFC 4226 with HMAC-SHA1 and dynamic truncation.
func hotp(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret) // #nosec G401 -- RFC 4226 mandates HMAC-SHA1
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

func isTOTPFormat(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// matchTOTP returns the step code matches within the skew window around now,
// or 0. Only steps after last are accepted, so a used code (or an older one)
// never works again. Every candidate is compared in constant time.
func matchTOTP(secret []byte, code string, now time.Time, last int64) int64 {
	if !isTOTPFormat(code) {
		return 0
	}
	var found int64
	cur := totpStep(now)
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if s <= last || s < 0 {
			continue
		}
		ok := subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s), totpDigits)), []byte(code)) == 1 // #nosec G115 -- s >= 0 checked above
		if ok && found == 0 {
			found = s
		}
	}
	return found
}

func base32NoPad(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// otpauthURI is the de facto Key URI format authenticator apps import. It is
// printed once by setup and never stored or logged.
func otpauthURI(secret []byte, host string) string {
	q := url.Values{
		"secret":    {base32NoPad(secret)},
		"issuer":    {"cortex-mcp"},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(totpDigits)},
		"period":    {fmt.Sprint(totpPeriod)},
	}
	return "otpauth://totp/" + url.PathEscape("cortex-mcp:"+host) + "?" + q.Encode()
}
