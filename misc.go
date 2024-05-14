package dirsyn

import "github.com/google/uuid"

type RFC2307 struct{}
type RFC3672 struct{}
type RFC4512 struct{}
type RFC4514 struct{}
type RFC4517 struct{}
type RFC4523 struct{}
type RFC4530 struct{}

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
func (r RFC4517) Boolean(x any) (err error) {
	switch tv := x.(type) {
	case bool:
	case string:
		if !(eqf(tv, `TRUE`) && eqf(tv, `FALSE`)) {
			err = errorTxt("Invalid Boolean " + tv)
		}
	default:
		err = errorBadType("Boolean")
	}

	return
}

/*
UUID returns an error following an analysis of x in the context of a UUID.

Note: this function utilizes Google's [uuid.Parse] method under the hood.

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
func (r RFC4530) UUID(x any) (err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if l := len(tv); l != 36 {
			err = errorBadLength("UUID", len(tv))
			return
		}
		raw = tv
	default:
		err = errorBadType("UUID")
		return
	}

	_, err = uuid.Parse(raw)

	return
}

/*
OID returns an error following an analysis of x in the context of either
a numeric OID or descriptor (descr) value.

From § 1.4 of RFC 4512:

	oid = descr / numericoid

See also [NumericOID] and [Descriptor] for ABNF productions.
*/
func (r RFC4512) OID(x any) (err error) {
	for _, err = range []error{
		r.NumericOID(x),
		r.Descriptor(x),
	} {
		if err == nil {
			break
		}
	}

	return
}

/*
OID is a wrapping alias of [RFC4512.OID].
*/
func (r RFC4517) OID(x any) (err error) {
	var s RFC4512
	err = s.OID(x)
	return
}

/*
Descriptor returns an error following an analysis of x in the context of
a descr, or descriptor, value.  See also [RFC4512.OID].

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
func (r RFC4512) Descriptor(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Descriptor", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Descriptor")
		return
	}

	// must begin with an alpha.
	if !isAlpha(rune(raw[0])) {
		err = errorTxt("Incompatible leading character: " + string(raw[0]))
		return
	}

	// can only end in alnum.
	if !isAlphaNumeric(rune(raw[len(raw)-1])) {
		err = errorTxt("Incompatible trailing character: " + string(raw[len(raw)-1]))
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
				err = errorTxt("Consecutive hyphens in descriptor")
				break
			}
			lastHyphen = true
		default:
			// invalid character (none of [a-zA-Z0-9\-])
			err = errorTxt("Incompatible character " + string(ch))
		}
	}

	return
}

/*
Descriptor is a wrapping alias of [RFC4512.Descriptor].
*/
func (r RFC4517) Descriptor(x any) (err error) {
	var s RFC4512
	err = s.Descriptor(x)
	return
}

/*
NumericOID returns an error following an analysis of x in the context of
a numeric OID.  See also [RFC4512.OID].

From § 1.4 of RFC 4512:

	numericoid = number 1*( DOT number )
	number  = DIGIT / ( LDIGIT 1*DIGIT )

	DIGIT   = %x30 / LDIGIT	  ; "0"-"9"
	LDIGIT  = %x31-39         ; "1"-"9"
	DOT     = %x2E            ; period (".")
*/
func (r RFC4512) NumericOID(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("DN", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("DN")
		return
	}

	if !('0' <= rune(raw[0]) && rune(raw[0]) <= '2') || raw[len(raw)-1] == '.' {
		err = errorTxt("Incompatible NumericOID leading character " + string(raw[len(raw)-1]))
		return
	}

	var last rune
	for _, c := range raw {
		switch {
		case c == '.':
			if last == c {
				err = errorTxt("Consecutive dots for NumericOID; cannot process")
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
NumericOID is a wrapping alias of [RFC4512.NumericOID].
*/
func (r RFC4517) NumericOID(x any) (err error) {
	var s RFC4512
	err = s.NumericOID(x)
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
func (r RFC4517) JPEG(x any) (err error) {
	var raw []uint8

	switch tv := x.(type) {
	case string:
		err = r.JPEG([]uint8(tv))
		return
	case []uint8:
		if len(tv) <= 12 {
			err = errorBadLength("JPEG", len(tv))
			return
		}
		raw = tv
	default:
		err = errorBadType("JPEG")
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
			err = errorTxt("Incompatible character for JPEG header: " + string(h))
			return
		}
	}

	footer := []rune{
		'\u00FF', // len-2
		'\u00D9', // len-1
	}

	if rune(raw[len(raw)-2]) != footer[0] {
		err = errorTxt("Incompatible character for JPEG footer: " + string(raw[len(raw)-2]))
	} else if rune(raw[len(raw)-1]) != footer[1] {
		err = errorTxt("Incompatible character for JPEG footer: " + string(raw[len(raw)-1]))
	}

	return
}

func splitUnescaped(str, sep, esc string) (slice []string) {
	slice = split(str, sep)
	for i := len(slice) - 2; i >= 0; i-- {
		if hasSfx(slice[i], esc) {
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
func (r RFC4517) SubstringAssertion(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Substring Assertion", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Substring Assertion")
		return
	}

	substrings := splitUnescaped(raw, `*`, `\`)
	for i, substring := range substrings {
		if len(substring) == 0 {
			continue
		} else if !isValidSubstring(substring) {
			err = errorTxt("Invalid Substring Assertion at component" + fmtInt(int64(i), 10))
			break
		}
	}

	return
}

func isValidSubstring(s string) bool {

	for i := 0; i < len(s); i++ {
		r := rune(s[i])
		if r == 0x5C {
			inc := runeLen(r)
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
UTF8String        = StringValue
StringValue       = dquote *SafeUTF8Character dquote

dquote            = %x22 ; " (double quote)
SafeUTF8Character = %x00-21 / %x23-7F /   ; ASCII minus dquote

	dquote dquote /       ; escaped double quote
	%xC0-DF %x80-BF /     ; 2 byte UTF-8 character
	%xE0-EF 2(%x80-BF) /  ; 3 byte UTF-8 character
	%xF0-F7 3(%x80-BF)    ; 4 byte UTF-8 character
*/
func isSafeUTF8(x any) (err error) {
	var raw []rune
	switch tv := x.(type) {
	case rune:
		raw = append(raw, tv)
	case string:
		if len(tv) == 0 {
			err = errorBadLength("UTF8 Safe Ranges", 0)
			return
		}
		for i := 0; i < len(tv); i++ {
			raw = append(raw, rune(tv[i]))
		}
	default:
		err = errorBadType("UTF8 Safe Ranges")
		return
	}

	var last rune
	for i := 0; i < len(raw) && err == nil; i++ {
		r := raw[i]
		switch runeLen(r) {
		case 1:
			// ASCII range w/o double-quote
			err = isSafeUTF1(string(r))
			if '"' == r && last != '\u005C' {
				err = errorTxt("Unescaped double-quote; not a UTF8 Safe Character")
			}
			last = r
		case 2:
			// UTF2 char
			err = isSafeUTF2(string(r))
		case 3:
			// UTF3 char
			err = isSafeUTF3(string(r))
		case 4:
			// UTF4 char
			err = isSafeUTF4(string(r))
		}
	}

	return
}

func isSafeUTF1(x string) (err error) {
	z := rune([]byte(x)[0])
	if !(ucIs(asciiRange, z) && z != '"') {
		err = errorTxt("Incompatible char for UTF0 (in ASCII Safe Range):" + x)
	}

	return
}

func isSafeUTF2(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	if !(ucIs(utf2aSafeRange, ch1) && ucIs(utf2bSafeRange, ch2)) {
		err = errorTxt("Incompatible chars for UTF2 (in UTF2 Safe Range): " + x)
	}

	return
}

func isSafeUTF3(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	if !(ucIs(utf3SafeRange, ch1) && ucIs(utf2bSafeRange, ch2) && ucIs(utf2bSafeRange, ch3)) {
		err = errorTxt("Incompatible chars for UTF3 (in UTF3 Safe Range): " + x)
	}

	return
}

func isSafeUTF4(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	ch4 := rune(z[3])
	if !(ucIs(utf4SafeRange, ch1) && ucIs(utf2bSafeRange, ch2) && ucIs(utf2bSafeRange, ch3) && ucIs(utf2bSafeRange, ch4)) {
		err = errorTxt("Incompatible chars for UTF4 (in UTF4 Safe Range): " + x)
	}

	return
}

/*
uTF8 returns an error following an analysis of x in the context of
one (1) or more UTF8 characters.

From § 1.4 of RFC 4512:

	UTF8    = UTF1 / UTFMB
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)
*/
func uTF8(x any) (err error) {
	var raw []rune
	switch tv := x.(type) {
	case rune:
		raw = append(raw, tv)
	case string:
		if len(tv) == 0 {
			err = errorBadLength("UTF-8", 0)
			return
		}
		for i := 0; i < len(tv); i++ {
			raw = append(raw, rune(tv[i]))
		}
	default:
		err = errorBadType("UTF-8")
		return
	}

	for i := 0; i < len(raw); i++ {
		if ucIs(utf1Range, rune(raw[i])) {
			continue
		} else if err = uTFMB(rune(raw[i])); err != nil {
			break
		}
	}

	return
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
			err = errorBadLength("UTFMB", 0)
			return
		}
		for i := 0; i < len(tv); i++ {
			raw = append(raw, rune(tv[i]))
		}
	default:
		err = errorBadType("UTFMB")
		return
	}

	for _, r := range raw {

		switch runeLen(r) {
		case 1:
			// UTF0
			if !ucIs(utf0Range, r) {
				err = errorTxt("Incompatible char for UTF0 (in UTFMB):" + string(r))
				return
			}
		case 2:
			// UTF2
			z := []byte(string(r))
			ch1 := rune(z[0])
			ch2 := rune(z[1])

			if !ucIs(utf2Range, ch1) || !ucIs(utf0Range, ch2) {
				err = errorTxt("Incompatible char for UTF2 (in UTFMB):" + string(r))
				return
			}

		case 3:
			z := []byte(string(r))
			z0 := rune(z[0])
			z1 := rune(z[1])
			z2 := rune(z[2])
			switch z0 {
			case '\u00e0':
				if !ucIs(utf3aRange, z1) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z2))
					return
				}
			case '\u00ed':
				if !ucIs(utf3cRange, z1) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z2))
					return
				}
			default:
				if !ucIs(utf3bRange, z0) && !ucIs(utf3dRange, z0) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z0))
					return
				}
				if !ucIs(utf0Range, z1) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z2))
					return
				}
			}

		case 4:
			// UTF4

			z := []byte(string(r))
			z0 := rune(z[0])
			z1 := rune(z[1])
			z2 := rune(z[2])
			z3 := rune(z[3])

			switch z0 {
			case '\u00f0':
				if !ucIs(utf4aRange, z1) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
					return
				}
				if !ucIs(utf0Range, z3) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
					return
				}
			case '\u00f4':
				if !ucIs(utf4cRange, z1) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
					return
				}
				if !ucIs(utf0Range, z3) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
					return
				}
			default:
				if !ucIs(utf4bRange, z0) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z0))
					return
				}
				if !ucIs(utf0Range, z1) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
					return
				}
				if !ucIs(utf0Range, z2) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
					return
				}
				if !ucIs(utf0Range, z3) {
					err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
					return
				}
			}

		default:
			err = errorTxt("Incompatible rune length for UTFMB")
			return
		}
	}

	return
}
