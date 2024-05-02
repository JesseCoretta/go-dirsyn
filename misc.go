package dirsyn

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var utf0Range *unicode.RangeTable

func isDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

func isAlpha(r rune) bool {
	return isLAlpha(r) || isUAlpha(r)
}

func isUAlpha(r rune) bool {
	return 'A' <= r && r <= 'Z'
}

func isLAlpha(r rune) bool {
	return 'a' <= r && r <= 'z'
}

func isBinChar(r rune) bool {
	return r == '0' || r == '1'
}

func isKeystring(x string) bool {
	if len(x) == 0 {
		return false
	}

	if !isAlpha(rune(x[0])) || rune(x[len(x)-1]) == '-' {
		return false
	}

	var last rune
	for i := 1; i < len(x); i++ {
		if last == '-' && rune(x[i]) == last {
			return false
		} else if !(isAlpha(rune(x[i])) || isDigit(rune(x[i])) || rune(x[i]) == '-') {
			return false
		}
		last = rune(x[i])
	}

	return true
}

func isNegativeInteger(x any) (is bool) {
	switch tv := x.(type) {
	case int:
		is = tv < 0
	case int8:
		is = tv < 0
	case int16:
		is = tv < 0
	case int32:
		is = tv < 0
	case int64:
		is = tv < 0
	}

	return
}

func isIntegerType(x any) (is bool) {
	switch x.(type) {
	case int, int8, int16, int32, int64:
		is = true
		return
	}

	return
}

/*
Boolean returns an error following an analysis of x in the context
of an ASN.1 BOOLEAN value.

From § 3.3.3 of RFC 4517:

	Boolean = "TRUE" / "FALSE"
*/
func Boolean(x any) (err error) {
	switch tv := x.(type) {
	case bool:
	case string:
		if !(strings.EqualFold(tv, `TRUE`) && strings.EqualFold(tv, `FALSE`)) {
			err = fmt.Errorf("Invalid Boolean '%s'", tv)
		}
	default:
		err = fmt.Errorf("Incompatible type '%T' for Boolean", tv)
	}

	return
}

/*
UUID returns an error following an analysis of x in the context of a UUID.

Note: this function utilizes Google's uuid.Parse method under the hood.

From § 3 of RFC 4122:

	UUID                   = time-low "-" time-mid "-"
	                         time-high-and-version "-"
	                         clock-seq-and-reserved
	                         clock-seq-low "-" node
	time-low               = 4hexOctet
	time-mid               = 2hexOctet
	time-high-and-version  = 2hexOctet
	clock-seq-and-reserved = hexOctet
	clock-seq-low          = hexOctet
	node                   = 6hexOctet
	hexOctet               = hexDigit hexDigit
	hexDigit =
	      "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9" /
	      "a" / "b" / "c" / "d" / "e" / "f" /
	      "A" / "B" / "C" / "D" / "E" / "F"
*/
func UUID(x any) (err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if l := len(tv); l != 36 {
			err = fmt.Errorf("Invalid length for UUID; want 36, got %d", l)
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for UUID", tv)
		return
	}

	_, err = uuid.Parse(raw)

	return
}

/*
OID returns an error following an analysis of x in the context of either
a numeric OID or descriptor (descr) value.

See also [NumericOID] and [Descriptor].
*/
func OID(x any) (err error) {
	for _, err = range []error{
		NumericOID(x),
		Descriptor(x),
	} {
		if err == nil {
			break
		}
	}

	return
}

/*
Descriptor returns an error following an analysis of x in the context of
a descr, or descriptor, value.  See also [OID].

From § 1.4 of RFC 4512:

	descr = keystring
	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT       ; "0"-"9"
	LDIGIT  = %x31-39             ; "1"-"9"
	HYPHEN  = %x2D                ; hyphen ("-")
*/
func Descriptor(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length DN")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for DN", tv)
		return
	}

	// must begin with an alpha.
	if !isAlpha(rune(raw[0])) {
		err = fmt.Errorf("Incompatible leading character '%c'", raw[0])
		return
	}

	// can only end in alnum.
	if !isAlphaNumeric(rune(raw[len(raw)-1])) {
		err = fmt.Errorf("Incompatible trailing character '%c'", raw[len(raw)-1])
		return
	}

	// watch hyphens to avoid contiguous use
	var lastHyphen bool

	// iterate all characters in raw, checking
	// each one for "descr" validity.
	for i := 0; i < len(raw) && err == nil; i++ {
		ch := rune(raw[i])
		switch {
		case isAlphaNumeric(ch):
			lastHyphen = false
		case ch == '-':
			if lastHyphen {
				// cannot use consecutive hyphens
				err = fmt.Errorf("Consecutive hyphens in descriptor")
				break
			}
			lastHyphen = true
		default:
			// invalid character (none of [a-zA-Z0-9\-])
			err = fmt.Errorf("Incompatible character '%c'", ch)
		}
	}

	return
}

/*
NumericOID returns an error following an analysis of x in the context of
a numeric OID.  See also [OID].

From § 1.4 of RFC 4512:

	numericoid = number 1*( DOT number )
	number  = DIGIT / ( LDIGIT 1*DIGIT )

	DIGIT   = %x30 / LDIGIT	  ; "0"-"9"
	LDIGIT  = %x31-39         ; "1"-"9"
	DOT     = %x2E            ; period (".")
*/
func NumericOID(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length DN")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for DN", tv)
		return
	}

	if !('0' <= rune(raw[0]) && rune(raw[0]) <= '2') || raw[len(raw)-1] == '.' {
		err = fmt.Errorf("Incompatible leading character '%c' for NumericOID", raw[0])
		return
	}

	var last rune
	for _, c := range raw {
		switch {
		case c == '.':
			if last == c {
				err = fmt.Errorf("Consecutive dots for NumericOID; cannot process")
				return
			}
			last = '.'
		case isDigit(c):
			last = c
			continue
		}
	}

	return
}

/*
JPEG returns an error following an analysis of x in the context
of a JFIF enveloped payload, which resembles the following:

	                      +- NULL (CTRL+@)
	                     /  +- DATA LINK ESCAPE (CTRL+P)
	                    /  /  +- ENVELOPE LITERAL
	                   +  +   |
	       ÿ  Ø  ÿ  à  |  |   |                         ÿ  Ù
	      -- -- -- -- -- -- ----                       -- --
	<SOF> FF D8 FF 0E 00 10 JFIF <variable image data> FF D9 <EOF>
*/
func JPEG(x any) (err error) {
	var raw []byte
	switch tv := x.(type) {
	case string:
		if len(tv) <= 12 {
			err = fmt.Errorf("Checksum failed for JPEG")
			return
		}
		raw = []byte(tv)
	default:
		err = fmt.Errorf("Incompatible type '%T' for JPEG", tv)
		return
	}

	header := []rune{
		'\u00FF',
		'\u00D8',
		'\u00FF',
		'\u00E0',
		'\u0000',
		'\u0010',
		'J',
		'F',
		'I',
		'F',
	}

	for idx, h := range header {
		if h != rune(raw[idx]) {
			err = fmt.Errorf("Incompatible character '%c' for JPEG header", h)
			return
		}
	}

	footer := []rune{
		'\u00FF', // len-2
		'\u00D9', // len-1
	}

	if rune(raw[len(raw)-2]) != footer[0] {
		err = fmt.Errorf("Incompatible character '%c' for JPEG footer", raw[len(raw)-2])
	} else if rune(raw[len(raw)-1]) != footer[1] {
		err = fmt.Errorf("Incompatible character '%c' for JPEG footer", raw[len(raw)-1])
	}

	return
}

func splitUnescaped(str, sep, esc string) (slice []string) {
	slice = strings.Split(str, sep)
	for i := len(slice) - 2; i >= 0; i-- {
		if strings.HasSuffix(slice[i], esc) {
			slice[i] = slice[i][:len(slice[i])-len(esc)] + sep + slice[i+1]
			slice = append(slice[:i+1], slice[i+2:]...)
		}
	}

	return
}

func strInSlice(r string, slice []string) bool {
	for i := 0; i < len(slice); i++ {
		if r == slice[i] {
			return true
		}
	}

	return false
}

func runeInSlice(r rune, slice []rune) bool {
	for i := 0; i < len(slice); i++ {
		if r == slice[i] {
			return true
		}
	}

	return false
}

func str2rune(str string) (r []rune) {
	for i := 0; i < len(str); i++ {
		r = append(r, rune(str[i]))
	}

	return
}

func isAlphaNumeric(r rune) bool {
	return unicode.Is(lAlphas, r) ||
		unicode.Is(uAlphas, r) ||
		unicode.Is(digits, r)
}

/*
SubstringAssertion returns an error following an analysis of x in the
context of a Substring Assertion.

From § 3.3.30 of RFC 4517:

	SubstringAssertion = [ initial ] any [ final ]

	initial  = substring
	any      = ASTERISK *(substring ASTERISK)
	final    = substring
	ASTERISK = %x2A  ; asterisk ("*")

	substring           = 1*substring-character
	substring-character = %x00-29
	                      / (%x5C "2A")  ; escaped "*"
	                      / %x2B-5B
	                      / (%x5C "5C")  ; escaped "\"
	                      / %x5D-7F
	                      / UTFMB
*/
func SubstringAssertion(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero-length Substring Assertion")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Substring Assertion", tv)
		return
	}

	substrings := splitUnescaped(raw, `*`, `\`)
	for i, substring := range substrings {
		if len(substring) == 0 {
			continue
		} else if !isValidSubstring(substring) {
			err = fmt.Errorf("Invalid Substring Assertion at component %d", i)
			break
		}
	}

	return
}

func isValidSubstring(s string) bool {

	for i := 0; i < len(s); i++ {
		r := rune(s[i])
		if r == 0x5C {
			inc := utf8.RuneLen(r)
			if i+inc < len(s) && (s[i+inc] == 0x2A || s[i+inc] == 0x5C) {
				i += inc
				continue
			}
		} else if err := uTFMB(r); err == nil {
			continue
		} else if (r >= 0x00 && r <= 0x29) || (r >= 0x2B && r <= 0x5B) || (r >= 0x5D && r <= 0x7F) {
			continue
		}

		return false
	}

	return true
}

/*
uTFMB returns an error following an analysis of x in the context of
one (1) or more UTFMB characters.
*/
func uTFMB(x any) (err error) {
	var raw []rune
	switch tv := x.(type) {
	case rune:
		raw = append(raw, tv)
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Invalid UTFMB string")
			return
		}
		for i := 0; i < len(tv); i++ {
			raw = append(raw, rune(tv[i]))
		}
	default:
		err = fmt.Errorf("Incompatible type '%T' for UTFMB", tv)
		return
	}

	for _, r := range raw {
		runeLength := utf8.RuneLen(r)

		switch runeLength {
		case 1:
			// UTF0
			if !unicode.Is(utf0Range, r) {
				err = fmt.Errorf("Incompatible char '%c' for UTF0 (in UTFMB)", r)
				return
			}
		case 2:
			// UTF2
			z := []byte(string(r))
			ch1 := rune(z[0])
			ch2 := rune(z[1])

			utf2Range := &unicode.RangeTable{R16: []unicode.Range16{
				{0x00C2, 0x00DF, 1},
			}}

			if !unicode.Is(utf2Range, ch1) || !unicode.Is(utf0Range, ch2) {
				err = fmt.Errorf("Incompatible char '%c' for UTF2 (in UTFMB)", r)
				return
			}

		case 3:
			utf3aRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x00A0, 0x00BF, 1},
			}}
			utf3bRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x00E1, 0x00EC, 1},
			}}
			utf3cRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x0080, 0x009F, 1},
			}}
			utf3dRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x00EE, 0x00EF, 1},
			}}

			z := []byte(string(r))
			z0 := rune(z[0])
			z1 := rune(z[1])
			z2 := rune(z[2])
			switch z0 {
			case '\u00e0':
				if !unicode.Is(utf3aRange, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z2)
					return
				}
			case '\u00ed':
				if !unicode.Is(utf3cRange, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z2)
					return
				}
			default:
				if !unicode.Is(utf3bRange, z0) && !unicode.Is(utf3dRange, z0) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z0)
					return
				}
				if !unicode.Is(utf0Range, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z2)
					return
				}
			}

		case 4:
			// UTF4
			utf4aRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x0090, 0x00BF, 1},
			}}
			utf4bRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x00F1, 0x00F3, 1},
			}}
			utf4cRange := &unicode.RangeTable{R16: []unicode.Range16{
				{0x0080, 0x008F, 1},
			}}

			z := []byte(string(r))
			z0 := rune(z[0])
			z1 := rune(z[1])
			z2 := rune(z[2])
			z3 := rune(z[3])

			switch z0 {
			case '\u00f0':
				if !unicode.Is(utf4aRange, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z2)
					return
				}
				if !unicode.Is(utf0Range, z3) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z3)
					return
				}
			case '\u00f4':
				if !unicode.Is(utf4cRange, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z2)
					return
				}
				if !unicode.Is(utf0Range, z3) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z3)
					return
				}
			default:
				if !unicode.Is(utf4bRange, z0) {
					err = fmt.Errorf("Incompatible char '%c' for UTF3 (in UTFMB)", z0)
					return
				}
				if !unicode.Is(utf0Range, z1) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z1)
					return
				}
				if !unicode.Is(utf0Range, z2) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z2)
					return
				}
				if !unicode.Is(utf0Range, z3) {
					err = fmt.Errorf("Incompatible char '%c' for UTF4 (in UTFMB)", z3)
					return
				}
			}

		default:
			err = fmt.Errorf("Incompatible rune length for UTFMB")
			return
		}
	}

	return
}

func init() {
	utf0Range = &unicode.RangeTable{R16: []unicode.Range16{{0x0080, 0x00BF, 1}}}
}
