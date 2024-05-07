package dirsyn

import (
	"testing"
)

func TestDeliveryMethod(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`any`,
		`mhs $ g3fax$ ia5 $ telephone`,
	} {
		if _, err := r.DeliveryMethod(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestPostalAddress(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`123 Fake Street$Palm Springs$CA$92111`,
		`The \$100000 Sweepstakes$10 Million Dollar Avenue$New York$NY`,
		`104 West Fake Street$Unit #10$Nowhere$MA$01234$US`,
	} {
		if _, err := r.PostalAddress(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}

func TestOtherMailbox(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`other$mailbox`,
		`test+,+$mailbox`,
	} {
		if _, err := r.OtherMailbox(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
