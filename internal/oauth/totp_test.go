package oauth

import (
	"encoding/base32"
	"net/url"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column (8 digits).
func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for sec, want := range map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	} {
		if got := hotp(secret, uint64(totpStep(time.Unix(sec, 0))), 8); got != want {
			t.Errorf("T=%d: %s, want %s", sec, got, want)
		}
	}
	if got := hotp(secret, uint64(totpStep(time.Unix(59, 0))), 6); got != "287082" {
		t.Errorf("6 digits: %s", got)
	}
}

func TestMatchTOTPWindowAndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	cur := totpStep(now)
	for _, d := range []int64{-1, 0, 1} {
		code := hotp(secret, uint64(cur+d), totpDigits)
		if got := matchTOTP(secret, code, now, 0); got != cur+d {
			t.Errorf("offset %d: step %d", d, got)
		}
		if got := matchTOTP(secret, code, now, cur+d); got != 0 {
			t.Errorf("offset %d accepted again after use", d)
		}
	}
	if matchTOTP(secret, hotp(secret, uint64(cur+2), totpDigits), now, 0) != 0 {
		t.Error("accepted a code two steps ahead")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", " 12345"} {
		if matchTOTP(secret, bad, now, 0) != 0 {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestOTPAuthURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	u, err := url.Parse(otpauthURI(secret, "cortex.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/cortex-mcp:cortex.example.com" ||
		q.Get("issuer") != "cortex-mcp" || q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("uri = %s", u)
	}
	got, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q.Get("secret"))
	if err != nil || string(got) != string(secret) {
		t.Fatalf("secret round trip = %q, %v", got, err)
	}
}
