package dirsyn

import (
	"testing"
)

func TestBool_codecov(t *testing.T) {
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
	//b.Eq(nil)
	//b.Eq(`fungii`)
	_ = b.String()

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

	//b.Eq(`true`)
	//b.Eq(false)
	//b.Eq(nil)
}
