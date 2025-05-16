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
		} else if ok && !even {
			t.Errorf("%s[%d] %T succeeded but should have failed", t.Name(), idx, raw)
		}
		b.Size()
		b.tag()
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
