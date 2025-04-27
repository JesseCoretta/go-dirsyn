package dirsyn

import (
	"fmt"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestInvalidFilter_String(t *testing.T) {
	f := invalidFilter{}
	if f.String() != `` {
		t.Errorf("%s failed: unable to print nil filter", t.Name())
	}
}

/*
This example demonstrates the means for properly assigning a value to
an instance of [AssertionValue].
*/
func ExampleAssertionValue_Set() {
	var av AssertionValue
	av.Set(`Lučić`)
	fmt.Printf("%s / %s\n",
		av.Escaped(),
		av.Unescaped())
	// Output: Lu\c4\8di\c4\87 / Lučić
}

/*
This example demonstrates the means for accessing the BER encoding of
an instance of [Filter].
*/
func ExampleFilter_BER() {
	var r RFC4515
	f, _ := r.Filter(`(&(sn=Lučić)(objectClass=person))`)

	packet, err := f.BER()
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

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterAnd_Index() {
	var r RFC4515
	f, _ := r.Filter(`(&(|(sn;lang-sl=Lučić)(employeeID=123456789))(objectClass=person))`)

	slice := f.Index(0).Index(1)
	fmt.Printf("%s\n", slice)
	// Output: (employeeID=123456789)
}

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterNot_Index() {
	var r RFC4515
	f, _ := r.Filter(`(!(&(objectClass=employee)(terminated=TRUE)))`)

	slice := f.Index(0)
	fmt.Printf("%s\n", slice.Choice())
	// Output: equalityMatch
}

/*
This example demonstrates the means for accessing a specific slice index
within the return instance of [Filter].
*/
func ExampleFilterOr_Index() {
	var r RFC4515
	f, _ := r.Filter(`(&(|(sn=Lučić)(employeeID=123456789))(objectClass=person))`)

	slice := f.Index(0)
	fmt.Printf("%s [%d]\n", slice.Choice(), slice.Len())
	// Output: or [2]
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
			Error:  `Unexpected end of filter`,
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
			Input:  `(givenName;lang-jp=ジェシー)`, // Jesse :)
			Output: `(givenName;lang-jp=\e3\82\b8\e3\82\a7\e3\82\b7\e3\83\bc)`,
			Choice: `equalityMatch`,
			Length: 1,
		},
		{
			Input:  `(sn;lang-sl:dn:=Lučić)`,
			Output: `(sn;lang-sl:dn:=Lu\c4\8di\c4\87)`,
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
			Input:  `(sn=Lučić)`,
			Output: `(sn=Lu\c4\8di\c4\87)`,
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
			Error:  `Invalid or malformed filter`,
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
		} else if _, err = filter.BER(); choice != `invalid` && err != nil {
			t.Errorf("%s[%d] encoding failed: %v", t.Name(), idx, err)
			continue
		}

		// Assuming we have a valid Filter, let's encode to
		// BER and then decode BER back into a Filter for
		// subsequent string comparison.
		if !filter.IsZero() {
			pkt, err := filter.BER()
			if err != nil {
				t.Errorf("%s[%d] BER encoding failed: %v", t.Name(), idx, err)
				continue
			}
			var filter2 Filter
			if filter2, err = r.Filter(pkt); err != nil {
				t.Errorf("%s[%d] BER decoding failed: %v", t.Name(), idx, err)
				continue
			}

			fstr := filter.String()
			fstr2 := filter2.String()
			if fstr != fstr2 {
				t.Errorf("%s[%d]:\nwant: %s\ngot: %s)\n",
					t.Name(), idx, fstr, fstr2)
				continue
			}
			filter.Index(9)
		}
	}
}

func TestFilter_codecov(t *testing.T) {

	var av AssertionValue
	av.Set([]byte(`hello`))
	av.Set(struct{}{})

	var ands FilterAnd
	ands.isFilter()
	ands.BER()

	var ors FilterOr
	ors.isFilter()
	ors.BER()

	var nots FilterNot
	nots.isFilter()
	nots.BER()

	var zerober *ber.Packet = &ber.Packet{}
	unmarshalItemFilterBER(zerober)
	unmarshalFilterBER(nil)
	unmarshalFilterBER(&ber.Packet{
		Description: `bogus`,
		Children:    []*ber.Packet{zerober},
	})
	unmarshalSetFilterBER(zerober)
	unmarshalFilterNotBER(zerober)
	unmarshalFilterSubstringsBER(zerober)
	unmarshalFilterSubstringsBER(&ber.Packet{
		Description: `bogus`,
		Children:    []*ber.Packet{zerober},
	})
	unmarshalEqualityFilterBER(zerober)
	unmarshalEqualityFilterBER(&ber.Packet{
		Description: `bogus`,
		Children:    []*ber.Packet{zerober},
	})
	unmarshalGeLeFilterBER(&ber.Packet{
		Description: `bogus`,
		Children:    []*ber.Packet{zerober},
	})
	unmarshalApproxFilterBER(&ber.Packet{
		Description: `bogus`,
		Children:    []*ber.Packet{zerober},
	})
	unmarshalExtensibleFilterBER(&ber.Packet{
		Description: `bogus`,
	})
	unmarshalFilterPresentBER(&ber.Packet{})

	var gEqual FilterGreaterOrEqual
	_ = gEqual.String()
	gEqual.Index(9)
	gEqual.IsZero()
	gEqual.Len()
	gEqual.BER()
	gEqual.tag()
	gEqual.isFilter()

	var lEqual FilterLessOrEqual
	_ = lEqual.String()
	lEqual.Index(9)
	lEqual.IsZero()
	lEqual.Len()
	lEqual.BER()
	lEqual.tag()
	lEqual.isFilter()

	var exts FilterExtensibleMatch
	exts.Index(9)
	exts.IsZero()
	_ = exts.String()
	exts.Len()
	exts.BER()
	exts.tag()
	exts.isFilter()
	exts.DNAttributes = true
	_ = exts.String()

	var substr FilterSubstrings
	_ = substr.String()
	substr.Index(9)
	substr.IsZero()
	substr.Len()
	substr.BER()
	substr.tag()
	substr.Substrings = SubstringAssertion{Any: AssertionValue(`blarg`)}
	substr.BER()
	substr.isFilter()
	substr.Type = AttributeDescription(`cn`)
	substr.BER()

	var eqly FilterEqualityMatch
	_ = eqly.String()
	eqly.Index(9)
	eqly.IsZero()
	eqly.Len()
	eqly.BER()
	eqly.tag()
	eqly.isFilter()

	var pres FilterPresent
	_ = pres.String()
	pres.Index(9)
	pres.IsZero()
	pres.Len()
	pres.BER()
	pres.tag()
	pres.isFilter()

	var aprx FilterApproximateMatch
	_ = aprx.String()
	aprx.Index(9)
	aprx.IsZero()
	aprx.Len()
	aprx.BER()
	aprx.tag()
	aprx.isFilter()

	var invalid invalidFilter
	_ = invalid.String()
	invalid.Index(9)
	invalid.IsZero()
	invalid.Len()
	invalid.BER()
	invalid.tag()
	invalid.isFilter()

	var attrdesc AttributeDescription
	attrdesc = AttributeDescription(`cn;lang-cn`)
	if attrdesc.Options()[0].Kind() != "tag" {
		t.Errorf("%s failed: Failed to obtain AttributeOption (tag)",
			t.Name())
		return
	}

	checkParenEncaps(`(bdf`, `fdhjds`)
	checkParenEncaps(`bdf`, `fdhjds)`)
	checkParenEncaps(`bdf`, `fdhjds`)
	checkParenEncaps(`Ibdf`, `fdhjds)`)

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
	parseItemFilter("(something=value")
	parseItemFilter(`47=83`)
	parseItemFilter(`47=_83`)
	parseItemFilter(`a:dn:1.2.3:=John`)
	parseExtensibleMatch(`a:dn:1.2.3.4`, `xxxx`)
	parseFilterNot(`4`)
	parseFilterNot(`uifeds\f43829`)
	marshalFilter(`uifeds\f43829`)
	marshalFilter(` `)
	parseComplexFilter(`_`, `&`)

	dnAttrSplit(`A:dn:Z`)
	dnAttrSplit(`A:DN:Z`)
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
		f, _ := r.Filter(filters[i%maxIdx])
		pkt, _ := f.BER()
		_, _ = r.Filter(pkt)
	}
}
