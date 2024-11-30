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

	result, err := objectIdentifierMatch(`2.5.4.3`, `2.5.4.3`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
	}

	result, err = objectIdentifierMatch(`2.5.4.3`, `2.5.4.0`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `FALSE`, result)
	}

	_, _ = objectIdentifierMatch(`2.5.4.3`, struct{}{})
	_, _ = objectIdentifierMatch(struct{}{}, struct{}{})

	type fakeType struct {
		Id string
	}

	fake := fakeType{`2.5.4.3`}
	result, err = objectIdentifierFirstComponentMatch(fake, `2.5.4.3`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
	}

	type bogusType struct {
		Id int
	}

	_, _ = objectIdentifierFirstComponentMatch(nil, `.`)
	_, _ = objectIdentifierFirstComponentMatch(`2.3.4.5`, `1.2.3.4`)
	_, _ = objectIdentifierFirstComponentMatch(bogusType{5}, `.`)
	_, _ = objectIdentifierFirstComponentMatch(DITStructureRuleDescription{RuleID: `4`}, `4`)
	_, _ = objectIdentifierFirstComponentMatch(fakeType{`descr`}, `2.5.4.3`)
	_, _ = objectIdentifierFirstComponentMatch(fakeType{`descr`}, nil)
	_, _ = objectIdentifierFirstComponentMatch(fakeType{`descr`}, `2..4.3`)
}
