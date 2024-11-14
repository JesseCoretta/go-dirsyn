package dirsyn

import (
	"testing"
)

func TestOID(t *testing.T) {
	var r RFC4512

	for idx, raw := range []string{
		`1.3.6.1.4.1.56521`,
		`cn`,
		`2.5.4.3`,
		`l`,
	} {
		if err := r.OID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v\n", t.Name(), idx, err)
		}
	}
}

func TestNumericOID(t *testing.T) {
	var r RFC4512

	for idx, raw := range []string{
		`1.3.6.1.4.1.56521`,
		`2.5.4.3`,
	} {
		if noid, err := r.NumericOID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v\n", t.Name(), idx, err)
		} else {
			t.Logf("%#v\n", noid.DotNotation.String())
		}
	}
}

func TestDescriptor(t *testing.T) {
	var r RFC4512

	for idx, raw := range []string{
		`cn`,
		`sn`,
		`randomAttr-v2`,
		`l`,
		`n`,
	} {
		if descr, err := r.Descriptor(raw); err != nil {
			t.Errorf("%s[%d] failed: %v\n", t.Name(), idx, err)
		} else {
			t.Logf("%s\n", string(descr))
		}
	}
}
