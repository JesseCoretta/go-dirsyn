package dirsyn

import (
	"testing"
)

func TestNumericString(t *testing.T) {
	for _, raw := range []any{
		`01 37 3748`,
		483982,
		`483982`,
		0,
		`00 00 00000000000000`,
	} {
		if err := NumericString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestUniversalString(t *testing.T) {
	for _, raw := range []string{
		`平仮名`,
		`This is a UniversalString.`,
		`This is@~@@~~~ not UniversalString ﺝﺦتﺣﺛrOH WAIT yes it is`,
	} {
		if err := UniversalString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestCountryString(t *testing.T) {
	for _, raw := range []string{
		`US`,
		`CA`,
		`UK`,
		`JP`,
	} {
		if err := CountryString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestBitString(t *testing.T) {
	var raw string = `'10100101'B`
	if err := BitString(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestIA5String(t *testing.T) {
	var raw string = `Jerry. Hello.`
	if err := IA5String(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestPrintableString(t *testing.T) {
	for _, raw := range []string{
		`WAT`,
		`This is a printable string.`,
	} {
		if err := PrintableString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
