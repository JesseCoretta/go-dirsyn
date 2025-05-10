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
			return
		} else if got := f.String(); len(got) != len(raw) {
			t.Errorf("%s failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), raw, got)
			return
		}
	}

	var tel FacsimileTelephoneNumber
	_ = tel.String()

	tel, _ = r.FacsimileTelephoneNumber(``)
	_ = tel.String()

	tel, _ = r.FacsimileTelephoneNumber(`A`)
	_ = tel.String()

	tel, _ = r.FacsimileTelephoneNumber(`+1 555 555 0280$b4Length$uncompressed$twoDimensional`)
	_ = tel.String()
	tel.set(uint(32))
	tel.set(uint(2))
}

func TestTelephoneNumber_SubstringMatch(t *testing.T) {
	for key, value := range map[string][]string{
		`+1 555 555 FILK`: {
			`+1*55555F*LK`,
		},
	} {
		for _, val := range value {
			if result, err := telephoneNumberSubstringsMatch(key, val); err != nil {
				t.Errorf("%s failed: %v", t.Name(), err)
			} else if !result.True() {
				t.Errorf("%s failed:\nwant: %s\ngot:  %s",
					t.Name(), `TRUE`, result)
			}
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

func TestTelephony_codecov(t *testing.T) {
	var r RFC4517

	_, _ = r.FacsimileTelephoneNumber(`\$`)
	_, _ = r.FacsimileTelephoneNumber(` $ `)
	_, _ = r.FacsimileTelephoneNumber(`twoDimensional$twoDimensional$`)

	_, _ = telephoneNumberMatch(`+1 555 555 FILK`, `+1 555 555 FILM`)

	_, _, _ = prepareTelephoneNumberAssertion(`+1 555 555 FILK`, `fh`)
	_, _, _ = prepareTelephoneNumberAssertion(`+1 555 555 FILK`, struct{}{})
	_, _, _ = prepareTelephoneNumberAssertion(nil, struct{}{})
	_, _, _ = prepareTelephoneNumberAssertion(struct{}{}, nil)

	_, _ = r.TelephoneNumber(nil)
	_, _ = r.TelephoneNumber(`naïve§`)
	_, _ = marshalTelephoneNumber(`+@@@AX`)

	var ffax FacsimileTelephoneNumber
	ffax.isSet(10394)

	_ = teletexSuffixValue(`ds世3`)
	_, _, _ = marshalTeletex([]string{})
	_, _, _ = marshalTeletex([]string{"a", "b", "c"})
	_, _, _ = marshalTeletex([]string{"graphic:this", "control:34", "misc:misc", "page:48", "private:psst"})
	_, _, _ = marshalTeletex([]string{"graphic:this", "control:34", "misc:misc", "page:48", "private:psst", "graphic:this", "control:34", "misc:misc", "page:48", "private:psst"})
	var uboverflow []string
	for len(uboverflow) < UBTeletexTerminalID+1 {
		uboverflow = append(uboverflow, "graphic:this")
	}

	_, _, _ = marshalTeletex(uboverflow)

	_ = facsimileTelephoneNumber(`+1 555 555 FILK$twoDimensional$twoDimensional`)
	_ = facsimileTelephoneNumber(`@K$twoDimensional$twoDimensional`)
	_ = telephoneNumber(`+1 555 555 FILK`)
	_ = telexNumber(`+1 555 555 FILK`)
	_ = teletexTerminalIdentifier(rune(88))
	_ = teletexTerminalIdentifier(`👩$👩`)
	_ = teletexTerminalIdentifier(`+1 555 555 FILK`)
	_ = teletexTerminalIdentifier(`P$control:abge$private:👩👩`)
	_ = teletexTerminalIdentifier(`👩👩P$control:abge$private:?>`)
	_ = teletexTerminalIdentifier(`👩👩P$controlly:abge$privape:?>`)
	_ = teletexTerminalIdentifier(`P$controlly:abge$privape:?>`)
	_ = teletexTerminalIdentifier(`P$control:abge$control:?>`)

	_, _ = marshalTelexNumber(`+12345US$getrac`)
	_, _ = marshalTelexNumber("1223$618$Hello?")
	_, _ = marshalTelexNumber("1223$618$Hello?👩👩")
	_, _ = marshalTelexNumber("👩$1223$618$...$👩")
	_, _ = marshalTelexNumber(`1 555 123 4567$`)

	teletexSuffixValue(`$$`)
	teletexSuffixValue(`@_+`)
	teletexSuffixValue(`\\\\\`)
}
