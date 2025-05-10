package dirsyn

import (
	"testing"
)

func TestUnicode_codecov(t *testing.T) {
	runes := []rune{
		'\U00100041',
		'\U0010FFFD',
		'\U0010FFFA',
		'\U00000062',
		'\U0010FFFB',
		'\U0010FFFC',
		'\U0010FFFF',
		'\U0010FFF1',
		'\U0000E000',
		'\U0000F400',
		rune(224), '\u00F3', '\u00F4',
		'\u00D8', '\u0465', '\u38FE',
		'\uEAFE', '👩', '\u200D',
		'\u00F0', '\u00F4', '\u00E0',
		'界', '世', 'こ', 'ん', 'に',
		'ち', 'は', '世', '界', 'í',
		'°', '\u00a0', 'ð', 'à',
	}

	if _, err := uTF8(runes); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		t.Logf("%#v\n", runes)
	}

	_ = isAlnum('c')

	assertUTF8String([]byte{0x62, 0x77})
	isUTF3([]byte{0xE0, 0x01, 0x2b})
	isUTF4([]byte{0xF1, 0x01, 0x2b})

	uTF8(struct{}{})
	assertRunes(byte(0x31))
	assertRunes([]byte{0x31})

	isSafeUTF1(`界`)
	isSafeUTF1(`1234`)
	isSafeUTF2(`1234`)
	isSafeUTF3(`1234`)
	isSafeUTF4(`1234`)
	isSafeUTF4(`1234`)
	isSafeUTF8(`1234界`)
	isSafeUTF8(`"""""`)
	isSafeUTF8(nil)

	badRunes := []rune{
		'A', 'c', 'd', 'g', '?', rune(0),
	}

	for _, bad := range badRunes {
		if err := uTFMB(bad); err == nil {
			t.Errorf("%s failed: expected error, got nothing", t.Name())
		}
	}

	_ = uTFMB([]rune{0xE0, 0x41})
}
