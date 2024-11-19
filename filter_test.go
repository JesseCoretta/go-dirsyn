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
		} else {
			filter.IsZero()
			_ = filter.String()
			filter.Len()
			filter.Choice()
		}
	}

	// test default filter using zero input
	var dfilt string = `(objectClass=*)`
	for _, def := range []any{
		``,
		nil,
	} {
		if out, err := r.Filter(def); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := out.String(); got != dfilt {
			t.Errorf("%s [present] failed:\nwant: %s\ngot:  %s\n",
				t.Name(), dfilt, got)
		}
	}

	if bad, err := r.Filter(struct{}{}); err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
		return
	} else {
		_ = bad.String()
		bad.Choice()
		bad.Len()
		bad.IsZero()
	}

	ext := &ExtensibleMatchFilter{DNAttributes: true}
	_ = ext.String()
	ext.Choice()
	ext.Len()
	ext.IsZero()

	and := &AndFilter{}
	_ = and.String()
	and.Choice()
	and.Len()
	and.IsZero()

	or := &OrFilter{}
	_ = or.String()
	or.Choice()
	or.Len()
	or.IsZero()

	not := &NotFilter{nil}
	_ = not.String()
	not.Choice()
	not.Len()
	not.IsZero()

	pf := PresentFilter{Desc: `&`}
	_ = pf.String()
	pf.Choice()
	pf.Len()
	pf.IsZero()

	emf := EqualityMatchFilter{Desc: `&`, Value: []byte{0x0}}
	_ = emf.String()
	emf.Choice()
	emf.Len()
	emf.IsZero()

	amf := ApproximateMatchFilter{Desc: `&`, Value: []byte{0x0}}
	_ = amf.String()
	amf.Choice()
	amf.Len()
	amf.IsZero()

	geo := GreaterOrEqualFilter{Desc: `&`, Value: []byte{0x0}}
	_ = geo.String()
	geo.Choice()
	geo.Len()
	geo.IsZero()

	leo := LessOrEqualFilter{Desc: `&`, Value: []byte{0x0}}
	_ = leo.String()
	leo.Choice()
	leo.Len()
	leo.IsZero()

	ssf := SubstringsFilter{
		Type: `&`,
		Substrings: SubstringAssertion{
			Initial: []byte{0x36, 0x38},
			Any:     []byte{0x36, 0x2a, 0x38},
			Final:   []byte{0x36, 0x3a},
		},
	}

	_ = ssf.String()
	ssf.Choice()
	ssf.Len()
	ssf.IsZero()

	checkFilterOIDs(`at`, `_lr`)
	checkFilterOIDs(`at`, ``)
	checkFilterOIDs(`1.3.5`, ``)
	checkFilterOIDs(`1.3.5`, `i`)
	checkFilterOIDs(``, `1.3.5`)
	checkFilterOIDs(`at`, `1.3.5`)
	checkFilterOIDs(``, `lr`)
	checkFilterOIDs(``, ``)
	checkFilterOIDs(`%$^&@#`, `#^@`)

	parseItemFilter(`4783`)
	parseItemFilter(`47=83`)
	parseItemFilter(`47=_83`)
	parseItemFilter(`a:dn:1.2.3:=John`)
	parseExtensibleMatch(`a:dn:1.2.3.4`, `xxxx`)
	parseNotFilter(`4`)
	parseNotFilter(`uifeds\f43829`)
	processFilter(`uifeds\f43829`)
	processFilter(` `)
	parseComplexFilter(`_`, `&`)
}
