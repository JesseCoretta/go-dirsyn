package dirsyn

import (
	"testing"
)

func TestTelexNumber(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`12345$US$getrac`,
	} {
		if err := r.TelexNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestTeletexTerminalIdentifier(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`P$control$graphic:abcd`,
		`P$control:a`,
		`P$control$page:`,
		`P$control$private:hi`,
	} {
		if err := r.TeletexTerminalIdentifier(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestFacsimileTelephoneNumber(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`+1 555 555 0280$b4Length$uncompressed$twoDimensional`,
	} {
		if _, err := r.FacsimileTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestTelephoneNumber(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`+1 555 555 0280`,
		`+1 800 GOT MILK`,
		`+1555FILK`,
	} {
		if _, err := r.TelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
