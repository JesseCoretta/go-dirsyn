package dirsyn

import (
	"testing"
)

func TestBitString(t *testing.T) {
	var r RFC4517

	var raw string = `'10100101'B`
	if result := bitString(raw); !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
		return
	}

	bs, err := r.BitString(raw)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if bs.IsZero() {
		t.Errorf("%s failed: instance is zero", t.Name())
	} else if got := bs.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
	}
}

func TestBitString_codecov(t *testing.T) {
	_, _ = assertBitString([]byte{})
	_, _ = assertBitString(struct{}{})
	_ = bitString([]byte{})
	_ = bitString(struct{}{})

	_, _ = bitStringMatch([]byte{}, struct{}{})
	_, _ = bitStringMatch([]byte(`'010110'B`), struct{}{})
	_, _ = bitStringMatch([]byte{}, []byte{})
	_, _ = bitStringMatch(struct{}{}, struct{}{})
	_, _ = bitStringMatch([]byte(`'010110'B`), []byte(`'01'B`))

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

	_ = stripTrailingZeros([]byte{0x1, 0x2, 0x0, 0x0}, 2)
	_ = stripTrailingZeros([]byte{0x1, 0x2, 0x0, 0x0}, 4)
	_ = stripTrailingZeros([]byte{}, 0)

}
