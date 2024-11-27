package dirsyn

/*
CountryString implements [§ 3.3.4 of RFC 4517]:

	CountryString  = 2(PrintableCharacter)

From [§ 1.4 of RFC 4512]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.4 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4
*/
type CountryString string

/*
String returns the string representation of the receiver instance.
*/
func (r CountryString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r CountryString) IsZero() bool { return len(r) == 0 }

func countryString(x any) (result Boolean) {
	_, err := marshalCountryString(x)
	result.Set(err == nil)
	return
}

/*
CountryString returns an error following an analysis of x in the context of
an [ISO 3166] country code. Note that specific codes -- though syntactically
valid -- should be verified periodically in lieu of significant world events.

[ISO 3166]: https://www.iso.org/iso-3166-country-codes.html
*/
func (r RFC4517) CountryString(x any) (CountryString, error) {
	return marshalCountryString(x)
}

func marshalCountryString(x any) (cs CountryString, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) != 2 {
			err = errorBadLength("Country String", 0)
			return
		}
		raw = tv
	case []byte:
		cs, err = marshalCountryString(string(tv))
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
DirectoryString implements the Directory String syntax.

From [§ 3.3.6 of RFC 4517]:

	DirectoryString = 1*UTF8

From [§ 1.4 of RFC 4512]:

	UTF8 = UTF1 / UTFMB
	UTFMB = UTF2 / UTF3 / UTF4
	UTF0  = %x80-BF
	UTF1  = %x00-7F
	UTF2  = %xC2-DF UTF0
	UTF3  = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	        %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4  = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	        %xF4 %x80-8F 2(UTF0)

From [ITU-T Rec. X.520 clause 2.6]:

	UnboundedDirectoryString ::= CHOICE {
		teletexString TeletexString(SIZE (1..MAX)),
		printableString PrintableString(SIZE (1..MAX)),
		bmpString BMPString(SIZE (1..MAX)),
		universalString UniversalString(SIZE (1..MAX)),
		uTF8String UTF8String(SIZE (1..MAX)) }

	DirectoryString{INTEGER:maxSize} ::= CHOICE {
		teletexString TeletexString(SIZE (1..maxSize,...)),
		printableString PrintableString(SIZE (1..maxSize,...)),
		bmpString BMPString(SIZE (1..maxSize,...)),
		universalString UniversalString(SIZE (1..maxSize,...)),
		uTF8String UTF8String(SIZE (1..maxSize,...)) }

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.6 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.6
[ITU-T Rec. X.520 clause 2.6]: https://www.itu.int/rec/T-REC-X.520
*/
type DirectoryString interface {
	String() string
	Choice() string
	IsZero() bool
	isDirectoryString() // differentiate from other interfaces
}

func (r BMPString) isDirectoryString()       {}
func (r UTF8String) isDirectoryString()      {}
func (r UniversalString) isDirectoryString() {}
func (r TeletexString) isDirectoryString()   {}
func (r PrintableString) isDirectoryString() {}

func (r BMPString) Choice() string       { return `bmpString` }
func (r UTF8String) Choice() string      { return `utf8String` }
func (r UniversalString) Choice() string { return `universalString` }
func (r TeletexString) Choice() string   { return `teletexString` }
func (r PrintableString) Choice() string { return `printableString` }

/*
DirectoryString returns an instance of [DirectoryString] alongside an error.

The following input types are accepted:

  - string (parsed as [UTF8String])
  - [UTF8String]
  - [PrintableString]
  - [TeletexString]
  - [BMPString]
*/
func (r RFC4517) DirectoryString(x any) (DirectoryString, error) {
	return marshalDirectoryString(x)
}

func directoryString(x any) (result Boolean) {
	_, err := marshalDirectoryString(x)
	result.Set(err == nil)
	return
}

func marshalDirectoryString(x any) (ds DirectoryString, err error) {
	switch tv := x.(type) {
	case UTF8String, string, []byte:
		ds, err = assertUTF8String(tv)
	case PrintableString:
		ds, err = marshalPrintableString(tv)
	case UniversalString:
		ds, err = marshalUniversalString(tv)
	case BMPString:
		ds, err = assertBMPString(tv)
	case TeletexString:
		ds, err = marshalTeletexString(tv)
	default:
		err = errorBadType("Directory String")
	}

	return ds, err
}

/*
UTF8String implements the UTF8 String syntax and abstraction.

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
type UTF8String string

/*
UTF8String returns an instance of [UTF8String] alongside an error
following an analysis of x in the context of a UTF8-compliant string.
*/
func (r RFC4512) UTF8String(x any) (UTF8String, error) {
	return assertUTF8String(x)
}

func assertUTF8String(x any) (u UTF8String, err error) {
	var raw string

	switch tv := x.(type) {
	case UTF8String:
		raw = string(tv)
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = errorBadType("UTF8String")
		return
	}

	/*
		if !utf8OK(raw) {
			err = errorTxt("UTF8String failed UTF8 validation")
			return
		}
	*/

	u = UTF8String(raw)
	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UTF8String) String() string { return string(r) }
func (r UTF8String) IsZero() bool   { return len(r) == 0 }

/*
PrintableString implements [§ 3.3.29 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From [§ 1.4 of RFC 4512]:

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

From [§ 3.2 of RFC 4517]:

	SLASH     = %x2F               ; forward slash ("/")
	COLON     = %x3A               ; colon (":")
	QUESTION  = %x3F               ; question mark ("?")

[§ 3.3.29 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type PrintableString string

/*
String returns the string representation of the receiver instance.
*/
func (r PrintableString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PrintableString) IsZero() bool { return len(r) == 0 }

func printableString(x any) (result Boolean) {
	_, err := marshalPrintableString(x)
	result.Set(err == nil)
	return
}

/*
PrintableString returns an error following an analysis of x in the context
of a [PrintableString].
*/
func (r RFC4517) PrintableString(x any) (PrintableString, error) {
	return marshalPrintableString(x)
}

func marshalPrintableString(x any) (ps PrintableString, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Printable String", 0)
			return
		}
		raw = tv
	case []byte:
		ps, err = marshalPrintableString(string(tv))
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

	ps = PrintableString(raw)

	return
}

/*
Encode returns the ASN.1 encoding of the receiver instance alongside an error.
*/
//func (r PrintableString) Encode() (b []byte, err error) {
//	b, err = asn1m(r)
//	return
//}

/*
Decode returns an error following an attempt to decode ASN.1 encoded bytes b into
the receiver instance. This results in the receiver being overwritten with new data.
*/
//func (r *PrintableString) Decode(b []byte) (err error) {
//	var rest []byte
//	rest, err = asn1um(b, r)
//	if err == nil {
//		if len(rest) > 0 {
//			err = errorTxt("Extra left-over content found during ASN.1 unmarshal: '" + string(rest) + "'")
//		}
//	}
//
//	return
//}

/*
UniversalString implements the Universal Character Set.

	UCS = 0x0000 through 0xFFFF
*/
type UniversalString string

/*
UniversalString returns an instance of [UniversalString] alongside an error
following an analysis of x in the context of a UniversalString.
*/
func (r RFC4517) UniversalString(x any) (UniversalString, error) {
	return marshalUniversalString(x)
}

func universalString(x any) (result Boolean) {
	_, err := marshalUniversalString(x)
	result.Set(err == nil)
	return
}

func marshalUniversalString(x any) (us UniversalString, err error) {
	var raw string

	switch tv := x.(type) {
	case UniversalString:
		raw = string(tv)
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = errorBadType("UniversalString")
		return
	}

	if !utf8OK(raw) {
		err = errorTxt("invalid UniversalString: failed UTF8 checks")
		return
	}

	us = UniversalString(raw)

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }

/*
IA5String implements [§ 3.2 of RFC 4517]:

	IA5 = 0x0000 through 0x00FF

[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
*/
type IA5String string

/*
String returns the string representation of the receiver instance.
*/
func (r IA5String) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r IA5String) IsZero() bool { return len(r) == 0 }

/*
IA5String returns an instance of [IA5String] alongside an error following
an analysis of x in the context of an IA5 String.
*/
func (r RFC4517) IA5String(x any) (ia5 IA5String, err error) {
	return marshalIA5String(x)
}

func iA5String(x any) (result Boolean) {
	_, err := marshalIA5String(x)
	result.Set(err == nil)
	return
}

func marshalIA5String(x any) (ia5 IA5String, err error) {
	var raw string
	if raw, err = assertString(x, 1, "IA5String"); err == nil {
		if err = checkIA5String(raw); err == nil {
			ia5 = IA5String(raw)
		}
	}

	return
}

func checkIA5String(raw string) (err error) {
	if len(raw) == 0 {
		err = errorTxt("Invalid IA5 String (zero)")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !ucIs(iA5Range, char) {
			err = errorTxt("Invalid IA5 String character: " + string(char))
			break
		}
	}

	return
}

/*
NumericString implements [§ 3.3.23 of RFC 4517]:

	NumericString = 1*(DIGIT / SPACE)

[§ 3.3.23 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23
*/
type NumericString string

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NumericString) IsZero() bool { return len(r) == 0 }

func numericString(x any) (result Boolean) {
	_, err := marshalNumericString(x)
	result.Set(err == nil)
	return
}

/*
NumericString returns an instance of [NumericString] alongside an error
following an analysis of x in the context of a Numeric String.
*/
func (r RFC4517) NumericString(x any) (NumericString, error) {
	return marshalNumericString(x)
}

func marshalNumericString(x any) (ns NumericString, err error) {
	var raw string
	if raw, err = assertNumericString(x); err == nil {
		for _, char := range raw {
			if !(isDigit(rune(char)) || char == ' ') {
				err = errorTxt("Incompatible character for Numeric String: " + string(char))
				break
			}
		}
	}

	if err == nil {
		ns = NumericString(raw)
	}

	return
}

func assertNumericString(x any) (raw string, err error) {
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		if isNegativeInteger(tv) {
			err = errorTxt("Incompatible sign (-) for Numeric String")
			break
		}
		var cint int64
		if cint, err = castInt64(tv); err == nil {
			raw = fmtInt(cint, 10)
		}
	case uint, uint8, uint16, uint32, uint64:
		var cuint uint64
		if cuint, err = castUint64(tv); err == nil {
			raw = fmtUint(cuint, 10)
		}
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Numeric String", 0)
			break
		}
		raw = tv
	default:
		err = errorBadType("Numeric String")
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
Deprecated: TeletexString implements the Teletex String, per [ITU-T Rec. T.61]

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
type TeletexString string

/*
String returns the string representation of the receiver instance.
*/
func (r TeletexString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r TeletexString) IsZero() bool { return len(r) == 0 }

/*
Deprecated: TeletexString returns an instance of [TeletexString] alongside
an error following an analysis of x in the context of a Teletex String, per
[ITU-T Rec. T.61].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
func (r RFC4517) TeletexString(x any) (TeletexString, error) {
	return marshalTeletexString(x)
}

func teletexString(x any) (result Boolean) {
	_, err := marshalTeletexString(x)
	result.Set(err == nil)
	return
}

func marshalTeletexString(x any) (ts TeletexString, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Teletex String", 0)
			return
		}
		raw = tv
	case []byte:
		ts, err = marshalTeletexString(string(tv))
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
OctetString implements [§ 3.3.25 of RFC 4517]:

	OctetString = *OCTET

[§ 3.3.25 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.25
*/
type OctetString []byte

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r OctetString) IsZero() bool { return r == nil }

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
func (r RFC4517) OctetString(x any) (OctetString, error) {
	return marshalOctetString(x)
}

func octetString(x any) (result Boolean) {
	_, err := marshalOctetString(x)
	result.Set(err == nil)
	return
}

func marshalOctetString(x any) (oct OctetString, err error) {
	var raw []byte
	if raw, err = assertOctetString(x); err != nil {
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

/*
BMPString implements the Basic Multilingual Plane per [ITU-T Rec. X.680].

The structure for instances of this type is as follows:

	T (30, Ox1E) N (NUM. BYTES) P{byte,byte,byte}

Tag T represents ASN.1 BMPString tag integer 30 (0x1E). Number N is an
int-cast byte value that cannot exceed 255. The remaining bytes, which
may be zero (0) or more in number, define payload P. N must equal size
of payload P.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type BMPString []uint8

/*
String returns the string representation of the receiver instance.

This involves unmarshaling the receiver into a string return value.
*/
func (r BMPString) String() string {
	if len(r) < 3 || r[0] != 0x1E {
		return ""
	}

	length := int(r[1])
	expectedLength := 2 + length*2
	if len(r) != expectedLength {
		return ""
	}

	var result []rune
	for i := 2; i < expectedLength; i += 2 {
		codePoint := (rune(r[i]) << 8) | rune(r[i+1])
		result = append(result, codePoint)
	}

	return string(result)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BMPString) IsZero() bool { return r == nil }

/*
BMPString marshals x into a BMPString (UTF-16) return value, returning
an instance of [BMPString] alongside an error.
*/
func (r X680) BMPString(x any) (BMPString, error) {
	return assertBMPString(x)
}

func assertBMPString(x any) (enc BMPString, err error) {
	var e string
	switch tv := x.(type) {
	case []uint8:
		e = string(tv)
	case BMPString:
		if len(tv) == 0 {
			break
		} else if len(tv) == 2 {
			if tv[0] != 0x1E || tv[1] != 0x0 {
				err = errorTxt("Invalid ASN.1 tag or length octet for empty string")
			} else {
				enc = BMPString{0x1E, 0x0}
			}
			return
		} else {
			if tv[0] != 0x1E {
				err = errorTxt("Invalid ASN.1 tag")
				return
			} else if int(tv[1]) != len(tv[2:]) {
				err = errorTxt("input string encoded length does not match length octet")
				return
			}
		}
		e = tv.String()
	case string:
		e = tv
	default:
		err = errorBadType("BMPString")
		return
	}

	if len(e) == 0 {
		// Zero length values are OK
		enc = BMPString{0x1E, 0x0}
		return
	}

	var result []byte
	result = append(result, 0x1E) // Add BMPString tag (byte(30))

	encoded := utf16Enc([]rune(e))
	length := len(encoded)
	if uint16(length) > uint16(255) {
		err = errorTxt("input string too long for BMPString encoding")
		return
	}
	result = append(result, byte(length))

	for _, char := range encoded {
		result = append(result, byte(char>>8), byte(char&0xFF))
	}

	enc = BMPString(result)

	return
}

func assertString(x any, min int, name string) (str string, err error) {
	switch tv := x.(type) {
	case []byte:
		str, err = assertString(string(tv), min, name)
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

func assertOctetString(in any) (raw []byte, err error) {
	switch tv := in.(type) {
	case []byte:
		raw = tv
	case OctetString:
		raw = []byte(tv)
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("OctetStringMatch")
	}

	return
}
