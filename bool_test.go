package dirsyn

import (
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
		_, err := r.Boolean(raw)
		ok := err == nil
		if !ok && even {
			t.Errorf("%s[%d] %T failed: %v", t.Name(), idx, raw, err)
		} else if ok && !even {
			t.Errorf("%s[%d] %T succeeded but should have failed", t.Name(), idx, raw)
		}
	}

	var b Boolean
	_ = b.Undefined()
	_ = b.String()

	_ = boolean(`TRUE`)
	_ = boolean(`FALSCH`)

	b.Set(`TRUE`)
	_ = b.String()
	b.Set(`FALSE`)
	_ = b.String()
	b.Set(nil)
	_ = b.String()
	b.Set(false)
	_ = b.String()

	var truthy bool
	b.Set(&truthy)
	_ = b.String()

	_, _ = booleanMatch(struct{}{}, true)
	_, _ = booleanMatch(true, struct{}{})
	_, _ = booleanMatch(false, true)
	_, _ = booleanMatch(Boolean{}, true)

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
