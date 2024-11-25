package dirsyn

import (
	"testing"
)

func TestUUID(t *testing.T) {
	var r RFC4530

	// We can skimp on tests, since we're just wrapping
	// a call to Google's uuid.Parse function.
	for idx, raw := range []string{
		`f81d4fae-7dec-11d0-a765-00a0c91e6bf6`,
	} {
		if _, err := r.UUID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestJPEG(t *testing.T) {
	var r RFC4517
	// TODO - add file reader (string) test using a
	// temporary file loaded with testJPEGData bytes.
	if err := r.JPEG(testJPEGData); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestMisc_codecov(t *testing.T) {
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

	pSOrIA5s(`界界界`)
	pSOrIA5s(`界$界$界`)
	pSOrIA5s(`$100000 Sweepstakes$10 Million Dollar Avenue$New York$NY`)

	b64dec([]byte{0x0, 0x1, 0x2, 0xff})
	isBase64([]byte{0x0, 0x1, 0x2, 0xff})
	isBase64(``)
	isBase64(struct{}{})

	dnAttrSplit(`A:dn:Z`)
	dnAttrSplit(`A:DN:Z`)

	hexEncode(``)
	hexEncode(nil)
	hexEncode([]byte{})
	hexEncode(`ABC`)
	hexEncode(`##`)

	hexDecode(``)
	hexDecode(nil)
	hexDecode([]byte{})
	hexDecode(`ABC`)
	hexDecode(`\u00XH`)
	hexDecode(`\zz`)
	hexDecode(`##`)

	isKeystring(`c--l`)
	isKeystring(`-`)
	isKeystring(``)
	isKeystring(`c界j`)
	isKeystring(`A`)
	isKeystring(`abc`)

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
		uTFMB(rune(0))
		isSafeUTF1(`界`)
		isSafeUTF1(`1234`)
		isSafeUTF2(`1234`)
		isSafeUTF3(`1234`)
		isSafeUTF4(`1234`)
		isSafeUTF4(`1234`)
		isSafeUTF8(`1234界`)
		isSafeUTF8(`"""""`)
		isSafeUTF8(nil)
	}

	_ = assertionValueRunes([]rune{}, false)

	var r0 X680
	var r1 X501
	var r2 X520
	var r3 RFC2307
	var r4 RFC3672
	var r5 RFC4512
	var r6 RFC4514
	var r7 RFC4515
	var r8 RFC4517
	var r9 RFC4523
	var r10 RFC4530

	r8.Boolean(`TRUE`)
	r8.Boolean(`FALSE`)
	r8.Boolean(`FALSCH`)
	r8.Boolean(`true`)
	r8.Boolean(true)
	r8.Boolean(`troo`)
	r8.Boolean(nil)
	r8.Boolean(struct{}{})

	r8.JPEG([]uint8(`dGVzdGluZzEyMzR0ZXN0aW5nNTY3OA==`)) // "testing1234testing5678"
	r8.JPEG(``)
	r8.JPEG([]uint8{0x0})
	r8.JPEG(nil)

	r10.UUID(`X`)
	r10.UUID(struct{}{})

	r0.URL()
	r1.URL()
	r2.URL()
	r3.URL()
	r4.URL()
	r5.URL()
	r6.URL()
	r7.URL()
	r8.URL()
	r9.URL()
	r10.URL()

	uTFMB(`a289fhjk`)

	isIntegerType(int32(3))
	isNegativeInteger(int(-3))
	isNegativeInteger(int8(-3))
	isNegativeInteger(int16(-3))
	isNegativeInteger(int32(-3))
	isNegativeInteger(int64(-3))

	castUint64(8)
	castUint64(uint(8))
	castUint64(uint8(3))
	castUint64(uint16(3))
	castUint64(uint32(33))
	castUint64(uint64(9))
	castUint64(struct{}{})

	castInt64(3)
	castInt64(int(8))
	castInt64(int8(3))
	castInt64(int16(3))
	castInt64(int32(33))
	castInt64(int64(9))
	castInt64(struct{}{})
}

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
}

/*
testJPEGData contains a byte sequence of a heavily truncated JPEG file (my github avatar).

Envelope-wise, this is a valid byte block and is used purely for unit testing, but really
only contains a couple of pixels worth of "image data". Even a heavily scaled-down -- but
complete -- JPEG block was too big to put in its raw byte form as in-line code.
*/
var testJPEGData []byte = []byte{
	0xff, 0xd8, 0xff, 0xe0, 0x0, 0x10,
	0x4a, 0x46, 0x49, 0x46, 0x0, 0x1,
	0x1, 0x1, 0xac, 0xff, 0xd9}
