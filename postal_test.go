package dirsyn

import (
	"testing"
)

func TestDeliveryMethod(t *testing.T) {
	for _, raw := range []string{
		`any`,
		`mhs $ g3fax$ ia5 $ telephone`,
	} {
		if err := DeliveryMethod(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestPostalAddress(t *testing.T) {
	for _, raw := range []string{
		`123 Fake Street$Palm Springs$CA$92111`,
		string(rune('\\')) + string(rune('$')),
		` #`,
	} {
		if err := PostalAddress(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
