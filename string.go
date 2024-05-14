package dirsyn

import (
	"encoding/asn1"
	"fmt"
)

/*
BitString is a type alias of [asn1.BitString], which can conform to § 3.3.2
of RFC 4517:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From § 1.4 of RFC 4512:

	SQUOTE  = %x27 ; single quote ("'")
*/
type BitString asn1.BitString

/*
String returns the string representation of the receiver instance.
*/
func (r BitString) String() (bs string) {
	if len(r.Bytes)*8 != r.BitLength {
		return
	}

	for _, b := range r.Bytes {
		bs += fmt.Sprintf("%b", b)
	}

	bs = string(rune('\'')) + bs +
		string(rune('\'')) +
		string(rune('B'))

	return
}

/*
BitString returns an error following an analysis of x in the context of
an ASN.1 BIT STRING.
*/
func (r RFC4517) BitString(x any) (bs BitString, err error) {
	var raw []byte
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			err = errorBadLength("BitString", 0)
			return
		}
		raw = tv
	case string:
		bs, err = r.BitString([]byte(tv))
		return
	default:
		err = errorBadType("BitString")
		return
	}

	// Last char MUST be 'B' rune, else die.
	if term := raw[len(raw)-1]; term != 'B' {
		err = errorTxt("Incompatible terminating character for BitString: " + string(term))
		return
	}

	// Trim terminating char
	raw = raw[:len(raw)-1]

	// Make sure there are enough remaining
	// characters to actually do something.
	if len(raw) < 3 {
		err = errorTxt("Incompatible remaining length for BitString: " + fmtInt(int64(len(raw)), 10))
		return
	}

	// Verify (and then remove) single quotes
	L := raw[0]
	R := raw[len(raw)-1]
	if L != '\'' || R != '\'' {
		err = errorTxt("Incompatible encapsulating characters BitString: " + string(L) + "/" + string(R))
		return
	}
	raw = raw[1 : len(raw)-1]

	for i := 0; i < len(raw); i++ {
		if !isBinChar(rune(raw[i])) {
			err = errorTxt("Incompatible non-binary character for BitString" + string(raw[i]))
			break
		}
	}

	if err == nil {
		var tx string
		var bss asn1.BitString

		for i := len(raw); i > 0; i -= 8 {
			if i-8 < 0 {
				tx = string(raw[:i])
			} else {
				tx = string(raw[i-8 : i])
			}

			bd, err := puint(tx, 2, 8)
			if err != nil {
				break
			}

			bss.Bytes = append(bss.Bytes, []byte{byte(bd)}...)
		}

		if err == nil {
			if _, err = asn1m(bss); err == nil {
				bss.BitLength = len(bss.Bytes) * 8
				bs = BitString(bss)
			}
		}
	}

	return
}

/*
CountryString implements § 3.3.4 of RFC 4517:

	CountryString  = 2(PrintableCharacter)

From § 1.4 of RFC 4512:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
*/
type CountryString string

func (r CountryString) String() string {
	return string(r)
}

/*
CountryString returns an error following an analysis of x in the context of
an ISO 3166 country code. Note that specific codes -- though syntactically
valid -- should be verified periodically in lieu of significant world events.
*/
func (r RFC4517) CountryString(x any) (cs CountryString, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) != 2 {
			err = errorBadLength("Country String", 0)
			return
		}
		raw = tv
	case []byte:
		cs, err = r.CountryString(string(tv))
		return
	default:
		err = errorBadType("Country String")
		return
	}

	if !isUAlpha(rune(raw[0])) || !isUAlpha(rune(raw[1])) {
		err = errorTxt("Incompatible characters for Country String: " +
			string(raw[0]) + "/" + string(raw[0]))
		return
	}

	var mdata []byte
	if mdata, err = asn1m(raw); err == nil {
		var testcss CountryString
		if _, err = asn1um(mdata, &testcss); err == nil {
			if testcss.String() == raw {
				cs = CountryString(raw)
			}
		}
	}

	return
}

/*
DirectoryString returns an error following an analysis of x in the context
of a Directory String.

From § 3.3.6 of RFC 4517:

	DirectoryString = 1*UTF8

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
func (r RFC4517) DirectoryString(x any) (err error) {
	err = uTF8(x)
	return
}

/*
PrintableString implements § 3.3.29 of RFC 4517:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From § 1.4 of RFC 4512:

	ALPHA   = %x41-5A / %x61-7A    ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT        ; "0"-"9"
	SQUOTE  = %x27                 ; single quote ("'")
	SPACE   = %x20                 ; space (" ")
	LPAREN  = %x28                 ; left paren ("(")
	RPAREN  = %x29                 ; right paren (")")
	PLUS    = %x2B                 ; plus sign ("+")
	COMMA   = %x2C                 ; comma (",")
	HYPHEN  = %x2D                 ; hyphen ("-")
	DOT     = %x2E                 ; period (".")
	EQUALS  = %x3D                 ; equals sign ("=")

From § 3.2 of RFC 4517:

	SLASH     = %x2F               ; forward slash ("/")
	COLON     = %x3A               ; colon (":")
	QUESTION  = %x3F               ; question mark ("?")
*/
type PrintableString string

func (r PrintableString) String() string {
	return string(r)
}

/*
PrintableString returns an error following an analysis of x in the context
of a PrintableString.
*/
func (r RFC4517) PrintableString(x any) (ps PrintableString, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Printable String", 0)
			return
		}
		raw = tv
	case []byte:
		ps, err = r.PrintableString(string(tv))
		return
	default:
		err = errorBadType("Printable String")
		return
	}

	chars := []rune{'\'', '(', ')', '+', ',', '-', '.', '=', '/', ':', '?', ' '}
	for i := 0; i < len(raw); i++ {
		r := rune(raw[i])
		if !(isAlphaNumeric(r) || runeInSlice(r, chars)) {
			err = errorTxt("Invalid Printable String character: " + string(r))
			return
		}
	}

	var mdata []byte
	if mdata, err = asn1m(raw); err == nil {
		var testpss PrintableString
		if _, err = asn1um(mdata, &testpss); err == nil {
			if testpss.String() == raw {
				ps = PrintableString(raw)
			}
		}
	}

	return
}

/*
UniversalString implements the Universal Character Set.

	UCS = 0x0000 through 0xFFFF
*/
type UniversalString string

/*
UniversalString returns an instance of [UniversalString] alongside an error
following an analysis of x in the context of a UniversalString.
*/
func (r RFC4517) UniversalString(x any) (us UniversalString, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Universal String", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Universal String")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !ucIs(uCSRange, char) {
			err = errorBadType("Invalid character for Universal String: " + string(char))
		}
	}

	if err == nil {
		us = UniversalString(raw)
	}

	return
}

/*
IA5String implements § 3.2 of RFC 4517:

	IA5 = 0x0000 through 0x00FF
*/
type IA5String string

func (r IA5String) String() string {
	return string(r)
}

/*
IA5String returns an instance of [IA5String] alongside an error following
an analysis of x in the context of an IA5 String.
*/
func (r RFC4517) IA5String(x any) (ia5 IA5String, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("IA5 String", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("IA5 String")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !ucIs(iA5Range, char) {
			err = errorTxt("Invalid IA5 String character: " + string(char))
		}
	}

	var mdata []byte
	if mdata, err = asn1m(raw); err == nil {
		var testcss IA5String
		if _, err = asn1um(mdata, &testcss); err == nil {
			if testcss.String() == raw {
				ia5 = IA5String(raw)
			}
		}
	}

	return
}

/*
NumericString implements § 3.3.23 of RFC 4517:

	NumericString = 1*(DIGIT / SPACE)
*/
type NumericString string

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string {
	return string(r)
}

/*
NumericString returns an instance of [NumericString] alongside an error
following an analysis of x in the context of a Numeric String.
*/
func (r RFC4517) NumericString(x any) (ns NumericString, err error) {
	var raw string
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		if isNegativeInteger(tv) {
			err = errorTxt("Incompatible sign (-) for Numeric String")
			return
		}
		raw = fmt.Sprintf("%d", tv)
	case uint, uint8, uint16, uint32, uint64:
		raw = fmt.Sprintf("%d", tv)
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Numeric String", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Numeric String")
		return
	}

	for _, char := range raw {
		if !(isDigit(rune(char)) || char == ' ') {
			err = errorTxt("Incompatible character for Numeric String: " + string(char))
			break
		}
	}

	if err == nil {
		ns = NumericString(raw)
	}

	return
}

/*
isT61Single returns a Boolean value indicative of a character match between input
rune r and one of the runes present within the t61NonContiguous global []rune
instance.
*/
func isT61Single(r rune) (is bool) {
	for _, char := range t61NonContiguous {
		if is = r == char; is {
			break
		}
	}

	return is
}

/*
Deprecated: TeletexString implements the Teletex String, per [T.61](https://www.itu.int/rec/T-REC-T.61).
*/
type TeletexString string

/*
String returns the string representation of the receiver instance.
*/
func (r TeletexString) String() string {
	return string(r)
}

/*
Deprecated: TeletexString returns an instance of [TeletexString] alongside
an error following an analysis of x in the context of a Teletex String, per
ITU-T Rec. T.61.
*/
func (r RFC4517) TeletexString(x any) (ts TeletexString, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Teletex String", 0)
			return
		}
		raw = tv
	case []byte:
		ts, err = r.TeletexString(string(tv))
		return
	default:
		err = errorBadType("Teletex String")
		return
	}

	for i := 0; i < len(raw); i++ {
		char := rune(raw[i])
		if !(isT61RangedRune(char) || isT61Single(char)) {
			err = errorTxt("Incompatible character for Teletex String: " + string(char))
			break
		}
	}

	if err == nil {
		ts = TeletexString(raw)
	}

	return
}

/*
OctetString implements § 3.3.25 of RFC 4517:

	OctetString = *OCTET
*/
type OctetString []byte

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string {
	return string(r)
}

/*
OctetString returns an instance of [OctetString] alongside an error
following an analysis of x in the context of an Octet String.
*/
func (r RFC4517) OctetString(x any) (oct OctetString, err error) {
	var raw []byte
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			// zero length values are OK
			return
		}
		raw = tv
	case string:
		oct, err = r.OctetString([]byte(tv))
		return
	default:
		err = errorBadType("Octet String")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !ucIs(octRange, char) {
			err = errorTxt("Incompatible Octet String character: " + string(char))
		}
	}

	if err == nil {
		oct = OctetString(raw)
	}

	return
}
