package dirsyn

import (
	"fmt"
	"testing"
)

func ExampleFilter_BEREncode() {
	var r RFC4515
	f, _ := r.Filter(`(&(sn=Lu\c4\8di\c4\87)(objectClass=person))`)

	packet, err := f.BEREncode()
	if err != nil {
		fmt.Println(err)
		return
	}

	at := packet.Children[0].Children[0].Value  // sn
	val := packet.Children[0].Children[1].Value // Lučić
	typ := packet.Children[0].Description

	fmt.Printf("%s: %s=%s\n", typ, at, val)
	// Output: equalityMatch: sn=Lu\c4\8di\c4\87
}

func TestFilter(t *testing.T) {
	var r RFC4515

	// Test cases sourced from RFC4515, go-ldap/filter.go, et al.
	for idx, x := range []struct {
		Input  any
		Output string
		Choice string
		Error  string
		Length int
	}{
		{
			Input:  `(objectGUID=\a)`,
			Output: ``,
			Error:  `Invalid filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(objectGUID=\zz)`,
			Output: ``,
			Error:  `Invalid filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(objectClass=`,
			Output: ``,
			Error:  `unexpected end of filter`,
			Choice: `invalid`,
		},
		{
			Input:  `(&(objectClass=*)(cn=Jesse))`,
			Output: `(&(objectClass=*)(cn=Jesse))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(sn=*ore*a)`,
			Output: `(sn=*ore*a)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
			Output: `(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(objectClass=top)`,
			Output: `(objectClass=top)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName~=Jessi)`,
			Output: `(givenName~=Jessi)`,
			Choice: `approxMatch`,
			Length: 1,
		},
		{
			Input:  `(n>=17485)`,
			Output: `(n>=17485)`,
			Choice: `greaterOrEqual`,
			Length: 1,
		},
		{
			Input:  `(cn=Babs Jensen)`,
			Output: `(cn=Babs Jensen)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName=)`,
			Output: `(givenName=)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(!(cn=Tim Howes))`,
			Output: `(!(cn=Tim Howes))`,
			Choice: `not`,
			Length: 1,
		},
		{
			Input:  `(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
			Output: `(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
			Choice: `or`,
			Length: 3,
		},
		{
			Input:  `(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
			Output: `(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))`,
			Choice: `and`,
			Length: 2,
		},
		{
			Input:  `(o=univ*of*mich*)`,
			Output: `(o=univ*of*mich*)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(seeAlso=)`,
			Output: `(seeAlso=)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(n<=17485)`,
			Output: `(n<=17485)`,
			Choice: `lessOrEqual`,
			Length: 1,
		},
		{
			Input:  `objectClass=top`,
			Output: `(objectClass=top)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:=John)`,
			Output: `(givenName:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:dn:=John)`,
			Output: `(givenName:dn:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:caseExactMatch:=John)`,
			Output: `(givenName:caseExactMatch:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(givenName:dn:2.5.13.5:=John)`,
			Output: `(givenName:dn:2.5.13.5:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:caseExactMatch:=John)`,
			Output: `(:caseExactMatch:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:dn:2.5.13.5:=John)`,
			Output: `(:dn:2.5.13.5:=John)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(cn:caseExactMatch:=Fred Flintstone)`,
			Output: `(cn:caseExactMatch:=Fred Flintstone)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(cn:=Betty Rubble)`,
			Output: `(cn:=Betty Rubble)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			Output: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(o:dn:=Ace Industry)`,
			Output: `(o:dn:=Ace Industry)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:1.2.3:=Wilma Flintstone)`,
			Output: `(:1.2.3:=Wilma Flintstone)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(:DN:2.4.6.8.10:=Dino)`,
			Output: `(:dn:2.4.6.8.10:=Dino)`,
			Choice: `extensibleMatch`,
			Length: 1,
		},
		{
			Input:  `(o=Parens R Us \28for all your parenthetical needs\29)`,
			Output: `(o=Parens R Us \28for all your parenthetical needs\29)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(cn=*\2A*)`,
			Output: `(cn=*\2A*)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  `(filename=C:\5cMyFile)`,
			Output: `(filename=C:\5cMyFile)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(bin=\00\00\00\04)`,
			Output: `(bin=\00\00\00\04)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn=Lu\c4\8di\c4\87)`,
			Output: `(sn=Lu\c4\8di\c4\87)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
			Output: `(1.3.6.1.4.1.1466.0=\04\02\48\69)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
			Output: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Output: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn=Mi*함*r)`,
			Output: `(sn=Mi*\ed\95\a8*r)`,
			Choice: `substrings`,
			Length: 1,
		},
		{
			Input:  ``,
			Output: `(objectClass=*)`,
			Choice: `present`,
			Length: 1,
		},
		{
			Input:  nil,
			Output: `(objectClass=*)`,
			Choice: `present`,
			Length: 1,
		},
		{
			Input:  struct{}{},
			Output: ``,
			Error:  `Invalid filter`,
			Choice: `invalid`,
			Length: 0,
		},
	} {
		filter, err := r.Filter(x.Input)
		if err != nil {
			if err.Error() != x.Error {
				t.Errorf("%s[%d] parse check failed: %v", t.Name(), idx, err)
			}
			continue
		} else if got := filter.String(); got != x.Output {
			t.Errorf("%s[%d] string check failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, x.Output, got)
			continue
		} else if choice := filter.Choice(); choice != x.Choice {
			t.Errorf("%s[%d] choice check failed:\nwant: %s\ngot:  %s\n",
				t.Name(), idx, x.Choice, choice)
			continue
		} else if l := filter.Len(); l != x.Length {
			t.Errorf("%s[%d] length check failed:\nwant: %d\ngot:  %d\n",
				t.Name(), idx, x.Length, l)
			continue
		} else if _, err = filter.BEREncode(); choice != `invalid` && err != nil {
			t.Errorf("%s[%d] encoding failed: %v", t.Name(), idx, err)
			continue
		}

		filter.IsZero()
	}

	// antipanic checks
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

func BenchmarkFilterParse(b *testing.B) {
	b.StopTimer()
	filters := []string{
		`(objectGUID=함수목록)`,
		`(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		`(objectGUID=\a)`,
		`(objectGUID=\zz)`,
		`(objectClass=`,
		`(&(objectClass=*)(cn=Jesse))`,
		`(sn=*ore*a)`,
		`(&(objectClass=*)(|(cn=Jesse)(cn=Courtney)))`,
		`(objectClass=top)`,
		`(givenName~=Jessi)`,
		`(n>=17485)`,
		`(cn=Babs Jensen)`,
		`(givenName=)`,
		`(!(cn=Tim Howes))`,
		`(|(employeeID=123456)(sn=Jensen)(cn=Babs J*))`,
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
		`(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
		`(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
		`(sn=Mi*함*r)`,
		``,
	}

	maxIdx := len(filters)
	var r RFC4515
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, _ = r.Filter(filters[i%maxIdx])
		//_, _ = f.BEREncode()
	}
}
