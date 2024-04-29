package dirsyn

import (
	"fmt"
	"unicode"
)

var (
	digits,
	lAlphas,
	uAlphas,
	uCSRange,
	octRange,
	iA5Range *unicode.RangeTable
)

/*
BitString returns an error following an analysis of x in the context of
an ASN.1 BIT STRING.

From § 3.3.2 of RFC 4517:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"
*/
func BitString(x any) (err error) {
	var raw []byte
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length BitString")
			return
		}
		raw = tv
	case string:
		err = BitString([]byte(tv))
		return
	default:
		err = fmt.Errorf("Incompatible type '%T' for BitString", tv)
		return
	}

	// Last char MUST be 'B' rune, else die.
	if term := raw[len(raw)-1]; term != 'B' {
		err = fmt.Errorf("Incompatible terminating character '%c' for BitString", term)
		return
	}

	// Trim terminating char
	raw = raw[:len(raw)-1]

	// Make sure there are enough remaining
	// characters to actually do something.
	if len(raw) < 3 {
		err = fmt.Errorf("Incompatible remaining length '%d' for BitString", len(raw))
		return
	}

	// Verify (and then remove) single quotes
	L := raw[0]
	R := raw[len(raw)-1]
	if L != '\'' || R != '\'' {
		err = fmt.Errorf("Incompatible encapsulating characters (%c/%c) for BitString", L, R)
		return
	}
	raw = raw[1 : len(raw)-1]

	for i := 0; i < len(raw); i++ {
		if !isBinChar(rune(raw[i])) {
			err = fmt.Errorf("Incompatible non-binary character '%c' for BitString", raw[i])
			break
		}
	}

	return
}

/*
CountryString returns an error following an analysis of x in the context of
an ISO 3166 country code. Note that specific codes -- though syntactically
valid -- should be verified periodically in lieu of significant world events.

From § 3.3.4 of RFC 4517:

	CountryString  = 2(PrintableCharacter)
*/
func CountryString(x any) (err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) != 2 {
			err = fmt.Errorf("Invalid length for CountryString")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for CountryString", tv)
		return
	}

	if !isUAlpha(rune(raw[0])) || !isUAlpha(rune(raw[1])) {
		err = fmt.Errorf("Incompatible char '%c%c' for CountryString", rune(raw[0]), rune(raw[1]))
	}

	return
}

/*
DirectoryString returns an error following an analysis of x in the context
of a DirectoryString.

Note this function implements a faux ASN.1 CHOICE, in that PrintableString,
UniversalString and (deprecated) TeletexString values are considered valid.
*/
func DirectoryString(x any) (err error) {
	for _, err = range []error{
		PrintableString(x),
		UniversalString(x),
		TeletexString(x),
	} {
		if err == nil {
			break
		}
	}

	return
}

/*
PrintableString returns an error following an analysis of x in the context
of a PrintableString.

From § 3.3.29 of RFC 4517:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
*/
func PrintableString(x any) (err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length PrintableString")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for PrintableString", tv)
		return
	}

	chars := []rune{'\'', '(', ')', '+', ',', '-', '.', '=', '/', ':', '?', ' '}
	for i := 0; i < len(raw); i++ {
		r := rune(raw[i])
		if !(isAlphaNumeric(r) || runeInSlice(r, chars)) {
			err = fmt.Errorf("Invalid PrintableString character '%c'", r)
			return
		}
	}

	return
}

/*
UniversalString returns an error following an analysis of x in the context
of a UniversalString.
*/
func UniversalString(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Universal String")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Universal String", tv)
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !unicode.Is(uCSRange, char) {
			err = fmt.Errorf("Invalid character '%c' for Universal String", char)
		}
	}

	return
}

/*
IA5String returns an error following an analysis of x in the context
of an IA5 String.
*/
func IA5String(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length IA5 String")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for IA5 String", tv)
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !unicode.Is(iA5Range, char) {
			err = fmt.Errorf("Invalid character '%c' for IA5 String", char)
		}
	}

	return
}

/*
NumericString returns an error following an analysis of x in the context
of a NumericString.

From § 3.3.23 of RFC 4517:

	NumericString = 1*(DIGIT / SPACE)
*/
func NumericString(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		if isNegativeInteger(tv) {
			err = fmt.Errorf("Incompatible sign (-) for Numeric String")
		}
		return
	case uint, uint8, uint16, uint32, uint64:
		return
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Incompatible (zero length) Numeric String")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Numeric String", tv)
		return
	}

	for _, char := range raw {
		if !(isDigit(rune(char)) || char == ' ') {
			err = fmt.Errorf("Incompatible character '%c' for Numeric String", char)
			break
		}
	}

	return
}

/*
t61Ranges defines a *unicode.RangeTable instance containing specific
16-bit and 32-bit character ranges that (partially) describe allowed
Unicode codepoints within a given T.61 value.

See also the t61NonContiguous global variable.
*/
var t61Ranges = &unicode.RangeTable{

	// 16-bit Unicode codepoints.
	R16: []unicode.Range16{
		{0x0009, 0x000f, 1}, // TAB through SHIFT-IN
		{0x0020, 0x0039, 1}, // ' ' .. '9'
		{0x0041, 0x005B, 1}, // 'a' .. '['
		{0x0061, 0x007A, 1}, // 'A' .. 'Z'
		{0x00A0, 0x00FF, 1},
		{0x008B, 0x008C, 1},
	},

	// 32-bit Unicode codepoints.
	R32: []unicode.Range32{
		{0x0126, 0x0127, 1},
		{0x0131, 0x0132, 1},
		{0x0140, 0x0142, 1},
		{0x0149, 0x014A, 1},
		{0x0152, 0x0153, 1},
		{0x0166, 0x0167, 1},
		{0x0300, 0x0304, 1},
		{0x0306, 0x0308, 1},
		{0x030A, 0x030C, 1},
		{0x0327, 0x0328, 1},
	},
}

/*
t61NonContiguous contains all non-contiguous characters (i.e.: those NOT incorporated
through the t61Ranges *unicode.RangeTable instance) that are allowed per T.61.  These
characters are as follows:

  - '\u009B' (�, npc)
  - '\u005C' (\)
  - '\u005D' (])
  - '\u005F' (_)
  - '\u003F' (?)
  - '\u007C' ([)
  - '\u007F' (])
  - '\u001d' (SS3, npc)
  - '\u0111' (đ)
  - '\u0138' (ĸ)
  - '\u0332' ( ̲)
  - '\u2126' (Ω)
  - '\u013F' (Ŀ)
  - '\u014B' (ŋ)
*/
var t61NonContiguous = []rune{
	'\u009B',
	'\u005C',
	'\u005D',
	'\u005F',
	'\u003F',
	'\u007C',
	'\u007F',
	'\u001d',
	'\u0111',
	'\u0138',
	'\u0332',
	'\u2126',
	'\u013F',
	'\u014B',
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
isT61RangedRune returns a Boolean value whether rune r matches an allowed
Unicode codepoint range.
*/
func isT61RangedRune(r rune) bool {
	return unicode.IsOneOf([]*unicode.RangeTable{t61Ranges}, r)
}

/*
TeletexString returns an error following an analysis of x in the context of a
(deprecated) Teletex -- or ITU-T Rec. T.61 -- string.
*/
func TeletexString(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Teletex String")
			return
		}
		raw = tv
	case []byte:
		err = TeletexString(string(tv))
		return
	default:
		err = fmt.Errorf("Incompatible type '%T' for Teletex String", tv)
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		char := rune(raw[i])
		if !(isT61RangedRune(char) || isT61Single(char)) {
			err = fmt.Errorf("Incompatible character '%c' for Teletex String", char)
		}
	}

	return
}

/*
OctetString returns an error following an analysis of x in the context of
an Octet String.

From § 3.3.25 of RFC 4517:

	OctetString = *OCTET
*/
func OctetString(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case []byte:
		err = OctetString(string(tv))
		return
	case string:
		if len(tv) == 0 {
			// zero length values are OK
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Octet String", tv)
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !unicode.Is(octRange, char) {
			err = fmt.Errorf("Incompatible character '%c' for Octet String", char)
		}
	}

	return
}

func init() {
	iA5Range = &unicode.RangeTable{R16: []unicode.Range16{{0x0000, 0x00FF, 1}}}
	octRange = iA5Range
	digits = &unicode.RangeTable{R16: []unicode.Range16{{0x0030, 0x0039, 1}}}
	lAlphas = &unicode.RangeTable{R16: []unicode.Range16{{0x0041, 0x005A, 1}}}
	uAlphas = &unicode.RangeTable{R16: []unicode.Range16{{0x0061, 0x007A, 1}}}

	uCSRange = &unicode.RangeTable{R32: []unicode.Range32{{0x0000, 0xFFFF, 1}}}
}
