package oauth

import (
	"strings"
	"unicode"
)

// maxNameRunes caps a client name on the login page and in "clients list".
const maxNameRunes = 64

// cleanName makes a client-supplied name safe to show to the owner and to
// log: it drops invalid UTF-8 and control and format characters (a bidi
// override could disguise a name on the consent page), combining marks
// (Mn, Me: stacked marks overflow the page), private-use and unassigned
// code points, and invisible fillers, collapses whitespace
// to single spaces, and caps the length.
func cleanName(s string) string {
	var b strings.Builder
	n, space := 0, false
	for _, r := range strings.ToValidUTF8(s, "") {
		switch {
		case unicode.IsSpace(r):
			space = true
		case unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me, unicode.Co, unicode.Cn) || invisibleFiller(r):
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

// invisibleFiller reports letters that render blank (Hangul and braille
// fillers); they pass the category checks but let a name look empty.
func invisibleFiller(r rune) bool {
	switch r {
	case 0x3164, 0x115F, 0x1160, 0x2800, 0xFFA0:
		return true
	}
	return false
}
