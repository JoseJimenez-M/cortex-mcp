package oauth

import (
	"strings"
	"unicode"
)

// maxNameRunes caps a client name on the login page and in "clients list".
const maxNameRunes = 64

// cleanName makes a client-supplied name safe to show to the owner and to
// log: it drops invalid UTF-8 and control and format characters (a bidi
// override could disguise a name on the consent page), collapses whitespace
// to single spaces, and caps the length.
func cleanName(s string) string {
	var b strings.Builder
	n, space := 0, false
	for _, r := range strings.ToValidUTF8(s, "") {
		switch {
		case unicode.IsSpace(r):
			space = true
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
		default:
			// A pending space is written only together with the rune after
			// it, so the result never ends (or starts) with a space.
			need := 1
			if space && b.Len() > 0 {
				need = 2
			}
			if n+need > maxNameRunes {
				return finishName(b.String())
			}
			if need == 2 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			n += need
			space = false
		}
	}
	return finishName(b.String())
}

func finishName(s string) string {
	if s == "" {
		return "unnamed client"
	}
	return s
}
