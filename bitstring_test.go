package dirsyn

import (
	"testing"
)

func TestBitString_codecov(t *testing.T) {
	_, _ = assertBitString([]byte{})
	_, _ = assertBitString(struct{}{})

	b, err := bitStringMatch(`'1010100'B`, `'1010000'B`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `FALSE`, b.String())
		return
	}

	b, err = bitStringMatch(`'1010100'B`, `'1010100'B`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, b.String())
		return
	}

}
