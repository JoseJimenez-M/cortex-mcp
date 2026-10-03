package oauth

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{
		"Claude":                   "Claude",
		"  Chat\tGPT \n":           "Chat GPT",
		"evil\u202egnp.exe":        "evilgnp.exe",
		"zero\u200bwidth":          "zerowidth",
		"bad\xffbyte":              "badbyte",
		"":                         "unnamed client",
		"\u3164":                   "unnamed client",
		"\u115f\u1160\u2800\uffa0": "unnamed client",
		"a\ue000b\u0378c":          "abc",
		"e\u0301\u0488x":           "ex",
		"Z" + strings.Repeat("\u0300\u0315\u0489", 40) + "algo": "Zalgo",
		"\x00\x01":               "unnamed client",
		strings.Repeat("a", 100): strings.Repeat("a", 64),
	} {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzCleanName(f *testing.F) {
	f.Add("Claude")
	f.Add("a\u202eb\x00c\xff")
	f.Fuzz(func(t *testing.T, s string) {
		got := cleanName(s)
		if got == "" || !utf8.ValidString(got) || utf8.RuneCountInString(got) > maxNameRunes {
			t.Fatalf("cleanName(%q) = %q", s, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me, unicode.Co, unicode.Cn) || (unicode.IsSpace(r) && r != ' ') {
				t.Fatalf("cleanName(%q) kept %U", s, r)
			}
		}
		if strings.HasPrefix(got, " ") || strings.HasSuffix(got, " ") || strings.Contains(got, "  ") {
			t.Fatalf("cleanName(%q) = %q has stray spaces", s, got)
		}
	})
}
