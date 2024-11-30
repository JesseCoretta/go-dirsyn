package dirsyn

import (
	"testing"
)

func TestCountryString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`US`,
		`CA`,
		`UK`,
		`JP`,
	} {
		if cs, err := r.CountryString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := cs.String(); raw != got {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}

	r.CountryString(nil)
	r.CountryString([]byte{})
	r.CountryString(``)
}

func TestCountryString_codecov(t *testing.T) {
	countryString(`US`)
	countryString(`FR`)
	countryString(`FRANCE`)
}
