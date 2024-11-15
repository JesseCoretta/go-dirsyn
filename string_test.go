package dirsyn

import (
	"testing"
)

func TestNumericString(t *testing.T) {
	var r RFC4517

	for _, raw := range []any{
		`01 37 3748`,
		483982,
		`483982`,
		0,
		`00 00 00000000000000`,
	} {
		if _, err := r.NumericString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestUniversalString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`平仮名`,
		`This is a UniversalString.`,
		`This is@~@@~~~ not UniversalString ﺝﺦتﺣﺛrOH WAIT yes it is`,
	} {
		if _, err := r.UniversalString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestOctetString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		``,
		`This is an OctetString.`,
	} {
		if _, err := r.OctetString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestCountryString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`US`,
		`CA`,
		`UK`,
		`JP`,
	} {
		if _, err := r.CountryString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestBitString(t *testing.T) {
	var r RFC4517

	var raw string = `'10100101'B`
	if _, err := r.BitString(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestIA5String(t *testing.T) {
	var r RFC4517

	var raw string = `Jerry. Hello.`
	if _, err := r.IA5String(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestPrintableString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`WAT`,
		`This is a printable string.`,
	} {
		if _, err := r.PrintableString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestDirectoryString(t *testing.T) {
	var r RFC4517

	for _, raw := range []any{
		`This is a Directory String.`,
		PrintableString(`this is a printable string`),
		UTF8String(`ZFKJ345325^&*$`),
		TeletexString(`maybe`),
	} {
		if _, err := r.DirectoryString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
