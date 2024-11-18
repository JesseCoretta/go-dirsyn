package dirsyn

import (
	"github.com/google/uuid"
)

/*
X501 serves as the receiver type for handling definitions sourced from
[ITU-T Rec. X.501].

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
type X501 struct{}

/*
URL returns the string representation of the [ITU-T Rec. X.501] document URL.

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func (r X501) URL() string {
	return `https://www.itu.int/rec/T-REC-X.501`
}

/*
X680 serves as the receiver type for handling definitions sourced from
[ITU-T Rec. X.680].

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type X680 struct {
	BMPLittleEndian bool // control endianness for BMPString handling
}

/*
URL returns the string representation of the [ITU-T Rec. X.680] document URL.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
func (r X680) URL() string {
	return `https://www.itu.int/rec/T-REC-X.680`
}

/*
X520 serves as the receiver type for handling definitions sourced from
[ITU-T Rec. X.520].

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
type X520 struct{}

/*
URL returns the string representation of the [ITU-T Rec. X.520] document URL.

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
func (r X520) URL() string {
	return `https://www.itu.int/rec/T-REC-X.520`
}

/*
RFC2307 serves as the receiver type for handling definitions sourced from
RFC 2307.
*/
type RFC2307 struct{}

/*
URL returns the string representation of the RFC 2307 document URL.
*/
func (r RFC2307) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc2307`
}

/*
RFC3672 serves as the receiver type for handling definitions sourced from
RFC 3672.
*/
type RFC3672 struct{}

/*
URL returns the string representation of the RFC 3672 document URL.
*/
func (r RFC3672) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc3672`
}

/*
RFC4512 serves as the receiver type for handling definitions sourced from
RFC 4512.
*/
type RFC4512 struct{}

/*
URL returns the string representation of the RFC 4512 document URL.
*/
func (r RFC4512) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4512`
}

/*
RFC4514 serves as the receiver type for handling definitions sourced from
RFC 4514.
*/
type RFC4514 struct{}

/*
URL returns the string representation of the RFC 4514 document URL.
*/
func (r RFC4514) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4514`
}

/*
RFC4515 serves as the receiver type for handling definitions sourced from
RFC 4515.
*/
type RFC4515 struct{}

/*
URL returns the string representation of the RFC 4515 document URL.
*/
func (r RFC4515) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4515`
}

/*
RFC4517 serves as the receiver type for handling definitions sourced from
RFC 4517.
*/
type RFC4517 struct{}

/*
URL returns the string representation of the RFC 4517 document URL.
*/
func (r RFC4517) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4517`
}

/*
RFC4523 serves as the receiver type for handling definitions sourced from
RFC 4523.
*/
type RFC4523 struct{}

/*
URL returns the string representation of the RFC 4523 document URL.
*/
func (r RFC4523) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4523`
}

/*
RFC4530 serves as the receiver type for handling definitions sourced from
RFC 4530.
*/
type RFC4530 struct{}

/*
URL returns the string representation of the RFC 4530 document URL.
*/
func (r RFC4530) URL() string {
	return `https://datatracker.ietf.org/doc/html/rfc4530`
}

func assertString(x any, min int, name string) (str string, err error) {
	switch tv := x.(type) {
	case string:
		if len(tv) < min && min != 0 {
			err = errorBadLength(name, 0)
			break
		}
		str = tv
	default:
		err = errorBadType(name)
	}

	return
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
		} else if !isXString(rune(x[i])) {
			return false
		}
		last = rune(x[i])
	}

	return true
}

func isXString(r rune) bool {
	return isAlpha(r) || isDigit(r) || r == '-'
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
	}

	return
}

func castInt64(x any) (i int64, err error) {
	switch tv := x.(type) {
	case int:
		i = int64(tv)
	case int8:
		i = int64(tv)
	case int16:
		i = int64(tv)
	case int32:
		i = int64(tv)
	case int64:
		i = tv
	default:
		err = errorBadType("any2int64")
	}

	return
}

func castUint64(x any) (i uint64, err error) {
	switch tv := x.(type) {
	case uint:
		i = uint64(tv)
	case uint8:
		i = uint64(tv)
	case uint16:
		i = uint64(tv)
	case uint32:
		i = uint64(tv)
	case uint64:
		i = tv
	default:
		err = errorBadType("any2uint64")
	}

	return
}

/*
Boolean returns a Go Boolean value alongside an error following an analysis
of x in the context of an ASN.1 BOOLEAN value.

Valid input types are native Go Booleans, string representations of Booleans
and nil.

If the input is a Go Boolean, true is equal to "TRUE" in the context of
directory values, while false is equal to "FALSE". The return error instance
shall always be nil.

If the input is a string, case is not significant in the matching process.
A value of "TRUE" returns a Go Boolean of true, while "FALSE" returns false.
Any other string value results in an error.

If the input is nil, the return is false, which simulates the "UNDEFINED"
behavior exhibited by most directory server products. The return error
instance shall always be nil.

All other input types return an error.

From [§ 3.3.3 of RFC 4517]:

	Boolean = "TRUE" / "FALSE"

[§ 3.3.3 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
*/
func (r RFC4517) Boolean(x any) (b bool, err error) {
	switch tv := x.(type) {
	case nil:
	case bool:
		b = tv
	case string:
		if !(eqf(tv, `TRUE`) && eqf(tv, `FALSE`)) {
			err = errorTxt("Invalid Boolean " + tv)
		} else {
			b = uc(tv) == `TRUE`
		}
	default:
		err = errorBadType("Boolean")
	}

	return
}

/*
UUID returns an error following an analysis of x in the context of a UUID.

Note: this function utilizes Google's [uuid.Parse] method under the hood.

From [§ 3 of RFC 4122]:

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

[§ 3 of RFC 4122]: https://datatracker.ietf.org/doc/html/rfc4122#section-3
*/
func (r RFC4530) UUID(x any) (u uuid.UUID, err error) {
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

	u, err = uuid.Parse(raw)

	return
}

/*
JPEG returns an error following an analysis of x in the context of a JFIF
enveloped payload, which resembles the following:

	                      +- NULL (CTRL+@)
	                     /  +- DATA LINK ESCAPE (CTRL+P)
	                    /  /  +- ENVELOPE LITERAL
	                   +  +   |
	       ÿ  Ø  ÿ  à  |  |   |                         ÿ  Ù
	      -- -- -- -- -- -- ----                       -- --
	<SOF> FF D8 FF 0E 00 10 JFIF <variable image data> FF D9 <EOF>

Note that only the envelope elements -- specifically the header and footer --
are read. Actual image data is skipped for performance reasons.

Valid input values are string and []byte.

If the input value is a string, it is assumed the value leads to a path
and filename of a JPEG image file.

If the input value is a []byte instance, it may be raw JPEG data, or Base64
encoded JPEG data. If Base64 encoded, it is decoded and processed.

All other input types result in an error.

Aside from the error instance, there is no return type for parsed JPEG
content, as this would not serve any useful purpose to end users in any
of the intended use cases for this package.

See also [§ 3.3.17 of RFC 4517].

[§ 3.3.17 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.17
*/
func (r RFC4517) JPEG(x any) (err error) {
	var raw []uint8

	switch tv := x.(type) {
	case string:
		// Read from file
		if raw, err = readFile(tv); err != nil {
			return
		}

		// Self-execute using the byte payload
		err = r.JPEG(raw)
		return
	case []uint8:
		if len(tv) <= 12 {
			err = errorBadLength("JPEG", len(tv))
			return
		}

		if isBase64(string(tv)) {
			var dec []byte
			if dec, err = b64dec(tv); err != nil {
				err = errorTxt("Bogus base64 payload")
				return
			}
			raw = dec
		} else {
			raw = tv
		}
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
SubstringAssertion implements SubstringAssertion per [§ 3.3.30 of RFC 4517]:

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

[§ 3.3.30 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30
*/
type SubstringAssertion []string

/*
Initial returns the first (left) component of the receiver instance, or
a zero string if not present.
*/
func (r SubstringAssertion) Initial() (i string) {
	if len(r) > 0 {
		if _i := r[0]; _i != `` {
			i = _i
		}
	}

	return
}

/*
Any returns the body of the receiver instance, in that the initial and
final components -- if present -- are not considered.
*/
func (r SubstringAssertion) Any() (a string) {
	if len(r) > 2 {
		a = `*` + join(r[1:len(r)-1], `*`) + `*`
	}

	return
}

/*
Final returns the final (right) component of the receiver instance, or
a zero string if not present.
*/
func (r SubstringAssertion) Final() (f string) {
	if len(r) > 0 {
		if _i := r[len(r)-1]; _i != `` {
			f = _i
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubstringAssertion) String() string {
	var _r []string
	for i := 0; i < len(r); i++ {
		r[i] = repAll(r[i], `\*`, `\\*`)
		_r = append(_r, r[i])
	}
	return join([]string(_r), `*`)
}

/*
SubstringAssertion returns an error following an analysis of x in the
context of a Substring Assertion.
*/
func (r RFC4517) SubstringAssertion(x any) (SubstringAssertion, error) {
	return processSubstringAssertion(x)
}

func processSubstringAssertion(x any) (ssa SubstringAssertion, err error) {
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

	ssa = SubstringAssertion(substrings)

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
		} else if ucIs(substrRange, r) {
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
	if raw, err = assertRunes(x); err != nil {
		return
	}

	funcs := map[int]func(string) error{
		2: isSafeUTF2,
		3: isSafeUTF3,
		4: isSafeUTF4,
	}

	var last rune
	for i := 0; i < len(raw) && err == nil; i++ {
		r := raw[i]
		switch rL := runeLen(r); rL {
		case 1:
			// ASCII range w/o double-quote
			err = isSafeUTF1(string(r))
			if '"' == r && last != '\u005C' {
				err = errorTxt("Unescaped double-quote; not a UTF8 Safe Character")
			}
			last = r
		case 2, 3, 4:
			// UTF2/3/4
			err = funcs[rL](string(r))
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

From [§ 1.4 of RFC 4512]:

	UTF8    = UTF1 / UTFMB
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
func uTF8(x any, zok ...bool) (u UTF8String, err error) {
	var raw []rune
	if raw, err = assertRunes(x, zok...); err != nil {
		return
	}

	for i := 0; i < len(raw); i++ {
		if ucIs(utf1Range, rune(raw[i])) {
			continue
		} else if err = uTFMB(rune(raw[i])); err != nil {
			break
		}
	}

	if err == nil {
		for i := 0; i < len(raw); i++ {
			u += UTF8String(raw[i])
		}
	}

	return
}

func assertRunes(x any, zok ...bool) (runes []rune, err error) {
	var zerook bool
	if len(zok) > 0 {
		zerook = zok[0]
	}
	switch tv := x.(type) {
	case rune:
		runes = append(runes, tv)
	case string:
		if len(tv) == 0 && !zerook {
			err = errorBadLength("Zero length rune", 0)
			break
		}
		for i := 0; i < len(tv); i++ {
			runes = append(runes, rune(tv[i]))
		}
	default:
		err = errorBadType("Not rune compatible")
	}

	return
}

/*
uTFMB returns an error following an analysis of x in the context of
one (1) or more UTFMB characters.
*/
func uTFMB(x any) (err error) {
	var raw []rune
	if raw, err = assertRunes(x); err != nil {
		return
	}

	funcs := map[int]func(rune) error{
		1: isUTF0,
		2: isUTF2,
		3: isUTF3,
		4: isUTF4,
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		r := raw[i]
		if funk, found := funcs[runeLen(r)]; found {
			err = funk(r)
			continue
		}
		err = errorTxt("Incompatible rune length for UTFMB")
	}

	return
}

// UTF0
func isUTF0(r rune) (err error) {
	if !ucIs(utf0Range, r) {
		err = errorTxt("Incompatible char for UTF0 (in UTFMB):" + string(r))
	}

	return
}

// UTF2
func isUTF2(r rune) (err error) {
	z := []byte(string(r))
	ch1 := rune(z[0])
	ch2 := rune(z[1])

	if !ucIs(utf2Range, ch1) || !ucIs(utf0Range, ch2) {
		err = errorTxt("Incompatible char for UTF2 (in UTFMB):" + string(r))
	}

	return
}

// UTF3
func isUTF3(r rune) (err error) {
	z := []byte(string(r))
	z0 := rune(z[0])
	z1 := rune(z[1])
	z2 := rune(z[2])

	switch z0 {
	case '\u00e0':
		if !ucIs(utf3aRange, z1) {
			err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z1))
		} else if !ucIs(utf0Range, z2) {
			err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z2))
		}
	case '\u00ed':
		if !ucIs(utf3cRange, z1) {
			err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z1))
		} else if !ucIs(utf0Range, z2) {
			err = errorTxt("Incompatible char for UTF3 (in UTFMB):" + string(z2))
		}
	default:
		var ok bool
		for _, ok = range []bool{
			ucIs(utf3bRange, z0),
			ucIs(utf3dRange, z0),
			ucIs(utf0Range, z1),
			ucIs(utf0Range, z2),
		} {
			if ok {
				return
			}
		}

		err = errorTxt("Incompatible char for UTF3 (in UTFMB): '" +
			string(z0) + "', '" + string(z1) + "', or '" + string(z2) + "'")
	}

	return
}

// UTF4
func isUTF4(r rune) (err error) {
	z := []byte(string(r))
	z0 := rune(z[0])
	z1 := rune(z[1])
	z2 := rune(z[2])
	z3 := rune(z[3])

	switch z0 {
	case '\u00f0':
		if !ucIs(utf4aRange, z1) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
		} else if !ucIs(utf0Range, z2) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
		} else if !ucIs(utf0Range, z3) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
		}
	case '\u00f4':
		if !ucIs(utf4cRange, z1) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
		} else if !ucIs(utf0Range, z2) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
		} else if !ucIs(utf0Range, z3) {
			err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
		}
	default:
		err = utf4Fallback(z0, z1, z2, z3)
	}

	return
}

func utf4Fallback(z0, z1, z2, z3 rune) (err error) {
	if !ucIs(utf4bRange, z0) {
		err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z0))
	} else if !ucIs(utf0Range, z1) {
		err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z1))
	} else if !ucIs(utf0Range, z2) {
		err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z2))
	} else if !ucIs(utf0Range, z3) {
		err = errorTxt("Incompatible char for UTF4 (in UTFMB):" + string(z3))
	}

	return
}
