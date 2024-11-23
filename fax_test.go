package dirsyn

import (
	"testing"
)

func TestFax(t *testing.T) {
	var r RFC4517

	orig := `3010310780010181020080a3050303000080` // hex encoded

	if _, err := r.Fax(orig); err != nil {
		t.Errorf("%s decoding failed: %v", t.Name(), err)
		return
	}
}

func TestFax_codecov(t *testing.T) {
	var r RFC4517

	r.Fax([]byte{0x1, 0x2, 0x3})
	r.Fax(struct{}{})
	r.Fax(`\zz`)

	var g3 G3FacsimileNonBasicParameters
	g3.Bytes = []byte{0x1, 0x2, 0x3}
	g3.Shift(8)
}
