package dirsyn

import (
	"testing"
)

func TestFilter(t *testing.T) {
	var r RFC4515

	for _, f := range []string{
		`(&(objectClass=*)(cn=Jesse))`,
		`(sn=*ore*a)`,
		`(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
		`(objectClass=top)`,
		`(givenName~=Jessi)`,
		`(n>=17485)`,
		`(n<=17485)`,
		`(!(cn=Frank Rizzo))`,
		`objectClass=top`,
		`(givenName:=John)`,
		`(givenName:dn:=John)`,
		`(givenName:caseExactMatch:=John)`,
		`(givenName:dn:2.5.13.5:=John)`,
		`(:caseExactMatch:=John)`,
		`(:dn:2.5.13.5:=John)`,
	} {
		if filter, err := r.Filter(f); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := filter.String(); got != f {
			switch filter.(type) {
			case SubstringsFilter, EqualityMatchFilter,
				PresentFilter, ExtensibleMatchFilter:

				// if the filter describes an item, then
				// don't fail on missing parenthetical
				// characters, since they're optional.
				if trim(got, `()`) != f {
					t.Errorf("%s failed:\nwant: %s\ngot:  %s\n",
						t.Name(), f, got)
				}
			default:
				t.Errorf("%s failed:\nwant: %s\ngot:  %s\n",
					t.Name(), f, got)
			}
		}
	}

	// test default filter using zero input
	var dfilt string = `(objectClass=*)`
	if def, err := r.Filter(``); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if got := def.String(); got != dfilt {
		t.Errorf("%s [present] failed:\nwant: %s\ngot:  %s\n",
			t.Name(), dfilt, got)
	}
}
