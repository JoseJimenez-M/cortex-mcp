package vault

import (
	"strings"
	"unicode"
)

// fold maps every rune to the smallest rune of its unicode.SimpleFold orbit,
// so two strings fold equal exactly when strings.EqualFold says they match
// (for valid UTF-8). One helper serves both the path protection rules and
// the lock keys, so "the same name" means the same thing everywhere.
// Unicode normalization (NFC versus NFD) is not folded: a known limit.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		return m
	}, s)
}

// foldEq reports whether a and b are the same name under fold.
func foldEq(a, b string) bool { return fold(a) == fold(b) }
