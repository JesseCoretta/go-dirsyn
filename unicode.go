package dirsyn

/*
unicode.go handles rune analysis and unicode ranging.
*/

import (
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

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

	u, err = uTF8(raw)
	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UTF8String) String() string { return string(r) }
func (r UTF8String) IsZero() bool   { return len(r) == 0 }

var (
	runeLen  func(rune) int                          = utf8.RuneLen
	decRune  func([]byte) (rune, int)                = utf8.DecodeRune
	ucIs     func(*unicode.RangeTable, rune) bool    = unicode.Is
	ucIn     func(rune, ...*unicode.RangeTable) bool = unicode.In
	uc1Of    func([]*unicode.RangeTable, rune) bool  = unicode.IsOneOf
	sfold    func(rune) rune                         = unicode.SimpleFold
	isLetter func(rune) bool                         = unicode.IsLetter
	utf8OK   func(string) bool                       = utf8.ValidString
	utf16Enc func([]rune) []uint16                   = utf16.Encode
	isSpace  func(rune) bool                         = unicode.IsSpace
	isPunct  func(rune) bool                         = unicode.IsPunct
)

var runeSelf rune = utf8.RuneSelf
var maxASCII rune = unicode.MaxASCII

var t61NonContiguous []rune

var (
	digits,
	lAlphas,
	uAlphas,
	uCSRange,
	octRange,
	iA5Range,
	ttxRange,
	t61Ranges,
	uTF8SubsetRange,
	lineCharRange,
	prsRange,
	telRange,
	substrRange,
	asciiRange,
	utf0Range,
	utf1Range,
	utf2Range,
	utf2aSafeRange,
	utf2bSafeRange,
	utf3aRange,
	utf3SafeRange,
	utf3bRange,
	utf3cRange,
	utf3dRange,
	utf4aRange,
	utf4SafeRange,
	utf4bRange,
	utf4cRange *unicode.RangeTable
)

var telephoneNumberRunes []rune

func isDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

func isAlpha(r rune) bool {
	return isLAlpha(r) || isUAlpha(r)
}

func isAlnum(r rune) bool {
	return isAlpha(r) || isDigit(r)
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

func isWHSP(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func runeInSlice(r rune, slice []rune) bool {
	for i := 0; i < len(slice); i++ {
		if r == slice[i] {
			return true
		}
	}

	return false
}

func isAlphaNumeric(r rune) bool {
	return ucIn(r, digits, uAlphas, lAlphas)
}

/*
isT61RangedRune returns a Boolean value whether rune r matches an allowed
Unicode codepoint range.
*/
func isT61RangedRune(r rune) bool {
	return uc1Of([]*unicode.RangeTable{t61Ranges}, r)
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
	if !(ucIs(utf2aSafeRange, ch1) &&
		ucIs(utf2bSafeRange, ch2)) {
		err = errorTxt("Incompatible chars for UTF2 (in UTF2 Safe Range): " + x)
	}

	return
}

func isSafeUTF3(x string) (err error) {
	z := []byte(string(x))
	ch1 := rune(z[0])
	ch2 := rune(z[1])
	ch3 := rune(z[2])
	if !(ucIs(utf3SafeRange, ch1) &&
		ucIs(utf2bSafeRange, ch2) &&
		ucIs(utf2bSafeRange, ch3)) {
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
	if !(ucIs(utf4SafeRange, ch1) &&
		ucIs(utf2bSafeRange, ch2) &&
		ucIs(utf2bSafeRange, ch3) &&
		ucIs(utf2bSafeRange, ch4)) {
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

	for i := 0; i < len(raw) && err == nil; i++ {
		if !ucIs(utf1Range, rune(raw[i])) {
			err = uTFMB(rune(raw[i]))
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
	case []rune:
		runes = tv
	case rune:
		runes = append(runes, tv)
	case byte:
		runes = append(runes, rune(tv))
	case []byte:
		runes, err = assertRunes(string(tv))
	case string:
		if len(tv) == 0 && !zerook {
			err = errorBadLength("Zero length rune", 0)
			break
		}
		runes = []rune(tv)
	default:
		err = errorBadType("Not rune compatible")
	}

	return
}

func assertionValueRunes(x any, zok ...bool) (err error) {
	var raw []rune
	if raw, err = assertRunes(x, zok...); err != nil {
		return
	}

	_err := errorTxt("Invalid assertionvalue characters")
	for i := 0; i < len(raw) && err == nil; i++ {
		if raw[i] == '\\' {
			// Check if there are at least
			// two more characters
			if i+3 > len(raw) {
				err = _err
			} else if !isHex(rune(raw[i+1])) || !isHex(rune(raw[i+2])) {
				// the next two characters are not hex
				err = _err
			}
			// Skip the next two characters, as
			// we've already vetted them
			i += 2
		} else if !ucIs(uTF8SubsetRange, rune(raw[i])) {
			err = uTFMB(rune(raw[i]))
		}
	}

	return
}

func isHex(char rune) bool {
	return ('0' <= char && char <= '9') ||
		('A' <= char && char <= 'F') ||
		('a' <= char && char <= 'f')
}

/*
uTFMB returns an error following an analysis of x in the context of
one (1) or more UTFMB characters.
*/
func uTFMB(x any) (err error) {
	var raw []rune
	if raw, err = assertRunes(x); err == nil {
		for i := 0; i < len(raw) && err == nil; i++ {
			r := rune(raw[i])
			var valid bool
			if valid, err = isUTFMB(r); !valid {
				err = errorTxt("Invalid UTFMB char: " + string(r))
				break
			}
		}
	}

	return
}

func isUTF0(b byte) bool {
	return b >= 0x80 && b <= 0xBF
}

func isUTF2(ub []byte) bool {
	return ub[0] >= 0xC2 && ub[0] <= 0xDF && isUTF0(ub[1])
}

func isUTF3(ub []byte) (b bool) {
	switch ub[0] {
	case 0xE0:
		b = ucIs(utf3aRange, rune(ub[1])) && isUTF0(ub[2])
	case 0xED:
		b = ucIs(utf3cRange, rune(ub[1])) && isUTF0(ub[2])
	case 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xEE, 0xEF:
		b = isUTF0(ub[1]) && isUTF0(ub[2])
	}

	return
}

func isUTF4(ub []byte) (b bool) {
	switch ub[0] {
	case 0xF0:
		b = ub[1] >= 0x90 && ub[1] <= 0xBF && isUTF0(ub[2]) && isUTF0(ub[3])
	case 0xF1, 0xF2, 0xF3:
		b = isUTF0(ub[1]) && isUTF0(ub[2]) && isUTF0(ub[3])
	case 0xF4:
		b = ucIs(utf4cRange, rune(ub[1])) && isUTF0(ub[2]) && isUTF0(ub[3])
	}

	return
}

func isUTFMB(r rune) (b bool, err error) {
	ub := make([]byte, 4)
	n := utf8.EncodeRune(ub, r)

	switch n {
	case 2:
		b = isUTF2(ub)
	case 3:
		b = isUTF3(ub)
	case 4:
		b = isUTF4(ub)
	}

	if !b {
		err = errorTxt("invalid leading byte for " + itoa(n) + "-byte sequence, or bad length")
	}

	return
}

func init() {

	uTF8SubsetRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0001, 0x0027, 1},
		{0x002B, 0x005B, 1},
		{0x005D, 0x007F, 1},
	}}

	iA5Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x00FF, 1},
	}}

	ttxRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0023, 1},
		{0x0025, 0x005B, 1},
		{0x005D, 0x00FF, 1},
	}}

	octRange = iA5Range

	digits = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0030, 0x0039, 1},
	}}

	lAlphas = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0041, 0x005A, 1},
	}}

	uAlphas = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0061, 0x007A, 1},
	}}

	uCSRange = &unicode.RangeTable{R32: []unicode.Range32{
		{0x0000, 0xFFFF, 1},
	}}

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
	t61NonContiguous = []rune{
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

	prsRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0020, 0x0020, 1},
		{0x0027, 0x0029, 1},
		{0x002b, 0x002f, 1},
		{0x003a, 0x003a, 1},
		{0x003f, 0x003f, 1},
	}}

	telRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0020, 0x0020, 1},
		{0x0022, 0x0022, 1},
		{0x0027, 0x0027, 1},
		{0x0028, 0x0028, 1},
		{0x002b, 0x002f, 1},
		{0x003a, 0x003a, 1},
		{0x003f, 0x003f, 1},
		{0x005c, 0x005c, 1},
	}}

	/*
		t61Ranges defines a *unicode.RangeTable instance containing specific
		16-bit and 32-bit character ranges that (partially) describe allowed
		Unicode codepoints within a given T.61 value.

		See also the t61NonContiguous global variable.
	*/
	t61Ranges = &unicode.RangeTable{

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

	lineCharRange = &unicode.RangeTable{R16: []unicode.Range16{
		// ASCII 00 through 7F with two exclusions ...
		{0x0000, 0x0023, 1}, // skip DOLLAR
		{0x0025, 0x005B, 1}, // skip ESC
		{0x005D, 0x007F, 1},
	}}

	substrRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0029, 1},
		{0x002B, 0x005B, 1},
		{0x005D, 0x007F, 1},
	}}

	utf0Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x00BF, 1},
	}}

	utf1Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x007F, 1},
	}}
	asciiRange = utf1Range

	utf2Range = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00C2, 0x00DF, 1},
	}}

	utf2aSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00C0, 0x00DF, 1},
	}}

	utf2bSafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x00BF, 1},
	}}

	utf3aRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00A0, 0x00BF, 1},
	}}

	utf3SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00E0, 0x00EF, 1},
	}}

	utf3bRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00E1, 0x00EC, 1},
	}}

	utf3cRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x009F, 1},
	}}

	utf3dRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00EE, 0x00EF, 1},
	}}

	utf4aRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0090, 0x00BF, 1},
	}}

	utf4SafeRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00F0, 0x00F7, 1},
	}}

	utf4bRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x00F1, 0x00F3, 1},
	}}

	utf4cRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0080, 0x008F, 1},
	}}
}
