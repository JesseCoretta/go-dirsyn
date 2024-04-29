package dirsyn

import (
	"testing"
)

func TestUTCTime(t *testing.T) {
	for idx, thyme := range []string{
		`9805061703Z`,
		`980506170306Z`,
		`620506170306-0500`,
	} {
		if err := UTCTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestGeneralizedTime(t *testing.T) {
	for idx, thyme := range []string{
		`20240229155701.0Z`,
		`20240229155703.00Z`,
		`20240229155702.000Z`,
		`20240229155703.0000Z`,
		`20240229155703.00000Z`,
		`20240229155703.000000Z`,
		`19980426135103Z`,
		`20240229155703-0500`,
		`20240229155703.0-0700`,
		`20240229155703.00-0700`,
		`20240229155703.000+1100`,
		`20240229155703.0000-0200`,
		`20240229155703.00000-0800`,
		`20200629155703.000000-0100`,
	} {
		if err := GeneralizedTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
