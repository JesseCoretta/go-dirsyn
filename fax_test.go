package dirsyn

import (
	"testing"
)

func TestFax(t *testing.T) {
	var r RFC4517

	orig := `3010310780010181020080a3050303000080` // hex encoded

	fax, err := r.Fax(orig)
	if err != nil {
		t.Errorf("%s decoding failed: %v", t.Name(), err)
		return
	}

	// Marshal the G3FacsimileBodyPart to ASN.1 encoded bytes
	b, err := fax.Encode()
	if err != nil {
		t.Errorf("%s encoding failed: %v", t.Name(), err)
		return
	}

	if got := string(b); got != orig {
		t.Errorf("%s encoding produced unexpected value;\nwant: %s\ngot:  %s\n",
			t.Name(), orig, got)
	}

}
