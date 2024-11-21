package dirsyn

/*
unicode.go handles rune analysis and unicode ranging.
*/

import (
	"unicode"
	"unicode/utf8"
)

var (
	runeLen func(rune) int                         = utf8.RuneLen
	decRune func([]byte) (rune, int)               = utf8.DecodeRune
	ucIs    func(*unicode.RangeTable, rune) bool   = unicode.Is
	uc1Of   func([]*unicode.RangeTable, rune) bool = unicode.IsOneOf
	sfold   func(rune) rune                        = unicode.SimpleFold
	utf8OK  func(string) bool                      = utf8.ValidString
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
	return ucIs(lAlphas, r) ||
		ucIs(uAlphas, r) ||
		ucIs(digits, r)
}

/*
isT61RangedRune returns a Boolean value whether rune r matches an allowed
Unicode codepoint range.
*/
func isT61RangedRune(r rune) bool {
	return uc1Of([]*unicode.RangeTable{t61Ranges}, r)
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
