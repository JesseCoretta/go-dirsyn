package dirsyn

import (
	"testing"
)

func TestDeliveryMethod(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`any`,
		`mhs $ g3fax $ ia5 $ telephone`,
	} {
		if dm, err := r.DeliveryMethod(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := dm.String(); got != raw {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
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
		if pa, err := r.PostalAddress(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := pa.String(); got != raw {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
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

	r.OtherMailbox(`界ac`)
}

func TestPostal_codecov(t *testing.T) {
	pSOrIA5s(nil)
	pSOrIA5s(`\\$`)
	pSOrIA5s(`\$`)
	pSOrIA5s(`......\$....!`)
	pSOrIA5s(`.$.$.$.$.$`)
	pSOrIA5s(`.$.$@$#$.$`)
	lineChar(`.#.$.$.$$`)
	lineChar(`.#.naïve.$.$$`)
	lineChar(string(rune('\U0010AAAA')) + `ð`)
	lineChar(`$abc$界$`)
	lineChar(string([]rune{'\u00e0', '$', '\u00FF'}))
}
