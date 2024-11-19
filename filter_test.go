package dirsyn

import (
	"testing"
)

func TestFilter(t *testing.T) {
	var r RFC4515

	for idx, f := range []string{
		`(&(objectClass=*)(cn=Jesse))`,
		`(sn=*ore*a)`,
		`(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
		`(objectClass=top)`,
		`(givenName~=Jessi)`,
		`(n>=17485)`,
		`(cn=Babs Jensen)`,
		`(givenName=)`,
		`(!(cn=Tim Howes))`,
		`(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
		`(o=univ*of*mich*)`,
		`(seeAlso=)`,
		`(n<=17485)`,
		`objectClass=top`,
		`(givenName:=John)`,
		`(givenName:dn:=John)`,
		`(givenName:caseExactMatch:=John)`,
		`(givenName:dn:2.5.13.5:=John)`,
		`(:caseExactMatch:=John)`,
		`(:dn:2.5.13.5:=John)`,
		`(cn:caseExactMatch:=Fred Flintstone)`,
		`(cn:=Betty Rubble)`,
		`(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		`(o:dn:=Ace Industry)`,
		`(:1.2.3:=Wilma Flintstone)`,
		`(:DN:2.4.6.8.10:=Dino)`,
		`(o=Parens R Us \28for all your parenthetical needs\29)`,
		`(cn=*\2A*)`,
		`(filename=C:\5cMyFile)`,
		`(bin=\00\00\00\04)`,
		`(sn=Lu\c4\8di\c4\87)`,
		`(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
	} {
		if filter, err := r.Filter(f); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := filter.String(); !eqf(got, f) {
			switch filter.(type) {
			case SubstringsFilter, EqualityMatchFilter,
				PresentFilter, ExtensibleMatchFilter:

				// if the filter describes an item, then
				// don't fail on missing parenthetical
				// characters, since they're optional.
				if !eqf(trim(got, `()`), f) {
					t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s\n",
						t.Name(), idx, f, got)
				}
			default:
				t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s\n",
					t.Name(), idx, f, got)
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
