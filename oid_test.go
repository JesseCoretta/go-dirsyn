package dirsyn

/*
NOTE: a bulk of the desirable test cases are already handled in
JesseCoretta/go-objectid, which is imported.
*/

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
		if _, err := r.NumericOID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v\n", t.Name(), idx, err)
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
		if _, err := r.Descriptor(raw); err != nil {
			t.Errorf("%s[%d] failed: %v\n", t.Name(), idx, err)
		}
	}
}

func TestOID_codecov(t *testing.T) {
	var x RFC4517
	x.NumericOID(`2.5.4.3`)
	x.Descriptor(`cn`)
	x.Descriptor(`cn#`)
	x.Descriptor(`c--n`)
	x.Descriptor(`c@n`)
}
