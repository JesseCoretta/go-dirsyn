package dirsyn

import (
	"testing"
)

func TestTelexNumber(t *testing.T) {
	for _, raw := range []string{
		`12345$US$getrac`,
	} {
		if err := TelexNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestTeletexTerminalIdentifier(t *testing.T) {
	for _, raw := range []string{
		`P$control$graphic:abcd`,
		`P$control:a`,
		`P$control$page:`,
		`P$control$private:hi`,
	} {
		if err := TeletexTerminalIdentifier(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestFacsimileTelephoneNumber(t *testing.T) {
	for _, raw := range []string{
		`+1 555 555 0280$b4Length$uncompressed$twoDimensional`,
	} {
		if err := FacsimileTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestTelephoneNumber(t *testing.T) {
	for _, raw := range []string{
		`+1 555 555 0280`,
		`+1 800 GOT MILK`,
		`+1555FILK`,
	} {
		if err := FacsimileTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
