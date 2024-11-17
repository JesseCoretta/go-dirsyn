package dirsyn

import (
	"testing"
)

func TestTelexNumber(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`12345$US$getrac`,
	} {
		if tn, err := r.TelexNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tn.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}
}

func TestTeletexTerminalIdentifier(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`P$graphic:abcd$misc:123`,
		`P$control:a`,
		`P$graphic:abf$page:`,
		`P$control:abge$private:hi`,
	} {
		if tti, err := r.TeletexTerminalIdentifier(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tti.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
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
