package dirsyn

import (
	"testing"
)

func TestUnicode_codecov(t *testing.T) {
	utf4Fallback('\U00000061', '\U00100061', '\U000000A9', '\U0000003F')
	utf4Fallback('\U0010FFFD', '\U0010FFFA', '\U0010FFFB', '\U0010FFFC')
	isUTF2(rune(10000))
	isUTF3('\u7FFF')
	isUTF2('í')
	isUTF2('°')
	isUTF2('\u00a0')
	isUTF2('ð')
	isUTF2('à')
	isUTF3('\U0010AAAA')
	isUTF3('\U0010AFFA')
	isUTF3('\U0010FFFA')
	isUTF3('\U0010FFFB')
	isUTF3('\U0010FFFD')
	isUTF3('\U0010FFFF')
	isUTF3('\U0010FF3B')
	isUTF4('\U0010FFFA')
	isUTF4('\U0010FFFB')
	isUTF4('\U0010FFFD')
	isUTF4('\U0010FFFF')
	isUTF4('\U0010FF3B')
	isUTF4(rune(90000))

	for _, roon := range []rune{
		'\u00D8', '\u0465', '\u38FE',
		'\uEAFE', '👩', 'A', '\u200D',
		'\u00f0', '\u00f4', '\u00e0',
		'界', '世',
	} {
		switch runeLen(roon) {
		case 1:
			isUTF0(roon)
		case 2:
			isUTF2(roon)
		case 3:
			isUTF3(roon)
		case 4:
			isUTF4(roon)
		}
		uTFMB(roon)
	}

	uTFMB(rune(0))
	uTFMB(`a289fhjk`)

	isSafeUTF1(`界`)
	isSafeUTF1(`1234`)
	isSafeUTF2(`1234`)
	isSafeUTF3(`1234`)
	isSafeUTF4(`1234`)
	isSafeUTF4(`1234`)
	isSafeUTF8(`1234界`)
	isSafeUTF8(`"""""`)
	isSafeUTF8(nil)

	str2rune(`#`)
	str2rune(`#8747832`)
	str2rune(`abcDEF`)
	assertRunes(``)
	uTFMB(`界界界`)
	uTFMB(nil)
	uTF8(nil, true)
	uTF8(nil, false)
	uTF8(`界`, false)
	uTF8(`界👩`, true)

	_ = assertionValueRunes([]rune{}, false)

}
