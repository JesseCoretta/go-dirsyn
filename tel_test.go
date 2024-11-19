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

	r.TelexNumber(``)
	r.TelexNumber(`333`)
	r.TelexNumber(`3\$3__3`)
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
		if f, err := r.FacsimileTelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := f.String(); len(got) != len(raw) {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}

	var tel FacsimileTelephoneNumber
	_ = tel.String()
	tel.Encode()
	tel.Decode([]byte{})

	tel, _ = r.FacsimileTelephoneNumber(``)
	_ = tel.String()

	tel, _ = r.FacsimileTelephoneNumber(`A`)
	_ = tel.String()

	tel, _ = r.FacsimileTelephoneNumber(`+1 555 555 0280$b4Length$uncompressed$twoDimensional`)
	_ = tel.String()
	tel.set(uint(2))
	tel.set(uint(32))
	tel.Decode([]byte{0x31, 0x0, 0x02})
}

func TestTelephoneNumber(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`+1 555 555 0280`,
		`+1 800 GOT MILK`,
		`+1555FILK`,
	} {
		if tel, err := r.TelephoneNumber(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := tel.String(); got != raw {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
		}
	}

	var tel TelephoneNumber
	_ = tel.String()

	tel, _ = r.TelephoneNumber(``)
	_ = tel.String()

	tel, _ = r.TelephoneNumber(`1`)
	_ = tel.String()
}
