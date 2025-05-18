package dirsyn

import (
	"fmt"
	"testing"
)

func TestBoolean_codecov(t *testing.T) {
	var r RFC4517
	for idx, raw := range []any{
		`TRUE`,
		`FALSCH`,
		`FALSE`,
		`troo`,
		`true`,
		``,
		true,
		struct{}{},
		nil,
		rune(10),
		"True",
	} {
		even := idx%2 == 0
		b, err := r.Boolean(raw)
		ok := err == nil
		if !ok && even {
			t.Errorf("%s[%d] %T failed: %v", t.Name(), idx, raw, err)
			return
		} else if ok && !even {
			t.Errorf("%s[%d] %T succeeded but should have failed", t.Name(), idx, raw)
			return
		}
		b.Size()
		b.sizeTagged(13)
		b.tag()

		var der []byte
		if der, err = b.DER(); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		}

		_ = derReadBoolean(&b, &DERPacket{data: der}, TagAndLength{})
		_ = derReadBoolean(&b, &DERPacket{data: der, offset: 1}, TagAndLength{Tag: 2, Length: 18})
		_ = derReadBoolean(&b, &DERPacket{data: der, offset: 1}, TagAndLength{Tag: 1, Length: 18})
		_ = derReadBoolean(&b, &DERPacket{data: []byte{0x1, 0x1, 0x0}}, TagAndLength{Tag: 1, Length: 3})
		_ = derReadBoolean(&b, &DERPacket{data: []byte{0x1, 0x1, 0xa}}, TagAndLength{Tag: 1, Length: 3})
		_ = derReadBoolean(&b, &DERPacket{data: []byte{0x1, 0x1, 0xff}}, TagAndLength{Tag: 1, Length: 3})
	}

	var b Boolean
	_ = b.Undefined()
	_ = b.String()
	_ = b.Bytes()

	_ = boolean(`TRUE`)
	_ = boolean(`FALSCH`)

	b.Set(`TRUE`)
	_ = b.String()
	_ = b.Bytes()
	b.Set(0x0)
	b.Set(`FALSE`)
	_ = b.String()
	b.Set(nil)
	_ = b.String()
	b.Set(false)
	b.Set(0xFF)
	b.Set([]byte{0x0})
	b.Set([]byte{0xFF})
	_ = b.String()
	b.SetBytes(0x00)
	b.SetBytes(0xFF)

	var truthy bool
	b.Set(&truthy)
	_ = b.String()

	_, _ = booleanMatch(struct{}{}, true)
	_, _ = booleanMatch(true, struct{}{})
	_, _ = booleanMatch(false, true)
	_, _ = booleanMatch(Boolean{}, true)

}

func ExampleBoolean_SetBytes() {
	var b Boolean
	b.SetBytes(0xFF) // TRUE
	fmt.Println(b)
	// Output: TRUE
}

func TestBoolean_Match(t *testing.T) {
	var b bool
	result, err := booleanMatch(`TRUE`, Boolean{&b})
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s", t.Name(), `FALSE`, result)
		return
	}
}
