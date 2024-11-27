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

	marshalSubstringAssertion(nil)
	marshalSubstringAssertion(``)
	marshalSubstringAssertion([]byte{})
	marshalSubstringAssertion(`thisis**bogus`)

	b, err := caseIgnoreSubstringsMatch(`this*isa*substring`, `this*isa*substring`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b.True() {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %s", t.Name(), b.String())
		return
	}

	b, err = caseExactSubstringsMatch(`this*isa*substring`, `This*isa*Substring`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !b.False() {
		t.Errorf("%s failed:\nwant: FALSE\ngot:  %s", t.Name(), b.String())
		return
	}

	//var r RFC4517

	//s, _ := r.SubstringAssertion(`this*this*this`)
	//s.substringsMatch(`thisathisethis`, true)
	//s.substringsMatch(`thisathisethis`, false)

	//s = SubstringAssertion{}
	//s.substringsMatch([]byte{})
	//s.substringsMatch(nil)
	//s.substringsMatch(SubstringAssertion{})
	//s.substringsMatch(``)

	//s = SubstringAssertion{Any: []byte(`this i* a substring`)}
	//s.substringsMatch(`this is a substring`, true)
	//s.substringsMatch(`athis is a substring`, false)
	//s = SubstringAssertion{
	//	Initial: []byte(`this`),
	//	Any:     []byte(`i* a `),
	//	Final:   []byte(`substring`),
	//}
	//s.substringsMatch(`athis is a substring`)
	//s.substringsMatch(`this is a substrink`)
	//s.substringsMatch(`this es a substring`)
}
