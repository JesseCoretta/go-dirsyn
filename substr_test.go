package dirsyn

import (
	"testing"
)

func TestSubstringAssertion(t *testing.T) {
	var r RFC4517
	for idx, raw := range []string{
		`substring*substring`,
		`substri*ng*thing`,
		`*substring*substring*`,
		`*substr*ing*end`,
		`substring*substring*substring`,
		`subst*`,
		`*ubstr`,
	} {
		if ssa, err := r.SubstringAssertion(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := ssa.String(); got != raw {
			t.Errorf("%s[%d] failed:\n\twant:%s\n\tgot: %s\n",
				t.Name(), idx, raw, got)
			t.Logf("RAW: %#v\n", ssa)
		}
	}
}

func TestSubstringAssertion_codecov(t *testing.T) {
	substrProcess1(`11*11`)
	substrProcess1(`aaaa`)
	substrProcess2(`11*11`)
	substrProcess2(`aaaa`)
	substrProcess3(`11*11`)
	substrProcess3(`aaaa`)
	substrProcess4(`11*11`)
	substrProcess4(`aaaa`)

	processSubstringAssertion(nil)
	processSubstringAssertion(``)
	processSubstringAssertion([]byte{})
	processSubstringAssertion(`thisis**bogus`)
}
