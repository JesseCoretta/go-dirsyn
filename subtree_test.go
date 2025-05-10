package dirsyn

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestSubtreeSpecification(t *testing.T) {
	var r RFC3672

	// Verify parsing of valid string-based SubSpec values
	for idx, raw := range []any{
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter and:{item:1.3.6.1.4.1,or:{item:cn,item:2.5.4.7}}}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter or:{item:1.3.6.1.4.1,not:item:1.3.6.1.5.5,and:{item:cn,item:2.5.4.7}}}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter item:1.3.6.1.4.1.56521}`,
		`{minimum 1, maximum 1}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter not:item:1.3.6.1.4.1.56521}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", specificExclusions { chopBefore "n=14", chopAfter "n=555", chopAfter "n=74,n=6" }, minimum 1, maximum 1, specificationFilter item:1.3.6.1.4.1.56521}`,
		`{}`,
	} {
		if v, err := r.SubtreeSpecification(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := v.String(); got != raw {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot: '%s'",
				t.Name(), idx, raw, got)
		} else {
			pkt, xerr := v.BER()
			if xerr != nil {
				t.Errorf("%s[%d] BER encoding failed: %v",
					t.Name(), idx, xerr)
				continue
			}

			var v2 SubtreeSpecification
			if v2, err = r.SubtreeSpecification(pkt); err != nil {
				t.Errorf("%s[%d] BER decoding failed: %v", t.Name(), idx, err)
				continue
			}
			if ngot := v2.String(); ngot != got {
				t.Errorf("%s[%d] post-BER check failed:\n\twant: '%s'\n\tgot: '%s'",
					t.Name(), idx, got, ngot)
			}

			if v.SpecificationFilter != nil {
				v.SpecificationFilter.Index(0)
				v.SpecificationFilter.Len()
				v.SpecificationFilter.IsZero()
				_ = v.SpecificationFilter.String()
			}
		}
	}
}

func TestSubtreeSpecification_codecov(t *testing.T) {
	var r RFC3672
	r.SubtreeSpecification(nil)
	r.SubtreeSpecification(``)
	r.SubtreeSpecification(`X`)
	r.SubtreeSpecification(byte(33))
	r.SubtreeSpecification(`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum -1, maximum 1, specificationFilter or:{item:1.3.6.1.4.1,not:item:1.3.6.1.5.5,and:{item:cn,item:2.5.4.7}}}`)

	_, _, _ = subtreeBase(rune(11))
	_, _, _ = subtreeBase(`value:...`)
	_, _ = subtreeRefinement(nil)

	_, _ = subtreeRefinement("any:{...}")

	_, _ = unmarshalRefinementBER(nil)

	var spec SubtreeSpecification
	spec.BER()
	spec.Base = "cn=1,cn=2,cn=3"
	spec.ChopSpecification.Exclusions = SpecificExclusions{
		SpecificExclusion{}}
	spec.BER()
	spec.ChopSpecification = ChopSpecification{}
	spec.SpecificationFilter = RefinementAnd{}
	spec.BER()
	_ = spec.String()

	var chop ChopSpecification
	chop.BER()

	_, _, _ = subtreeExclusions("{", 0)
	_, _, _ = subtreeExclusions("{chopBefore:cn=y,chopAfter:cn=x}", 0)
	_, _, _ = deconstructExclusions("{chopAfter:cn=x}", 0)

	var orref RefinementOr
	orref.Push(nil)
	orref.BER()
	_ = orref.String()
	orref.Index(2)
	orref.isRefinement()
	oi1, _ := parseOr("item:2.6.5.0")
	orref.Push(oi1)
	orref.Push("item:2.6.5.5")
	orref = append(orref, RefinementItem(``))
	orref.BER()

	var andref RefinementAnd
	andref.Push(nil)
	andref.BER()
	_ = andref.String()
	andref.Index(2)
	andref.isRefinement()
	ai1, _ := parseAnd("item:2.6.5.0")
	andref.Push(ai1)
	andref.Push("item:2.6.5.5")
	andref = append(andref, RefinementItem(``))
	andref.BER()

	var excls SpecificExclusions
	excls.BER()
	_ = excls.String()

	var excl SpecificExclusion
	excl.BER()
	_ = excl.String()

	var iref RefinementItem
	iref.BER()
	iref.Choice()
	_ = iref.String()
	iref.Len()
	iref.Index(1)
	iref.isRefinement()

	var nref RefinementNot
	nref.BER()
	_ = nref.String()
	nref.Len()
	nref.Index(1)
	nref.isRefinement()

	var ivref invalidRefinement
	ivref.BER()
	ivref.Index(2)
	ivref.isRefinement()
	ivref.IsZero()
	ivref.Len()
	ivref.Choice()
	_ = ivref.String()

	checkSubtreeEncaps(`fjhdjk`)
	checkSubtreeEncaps(`{..`)
	subtreeExclusions(`F`, 0)
	subtreeExclusions(`a`, 0)

	parseItem("item:something")
	parseItem("item:")
	parseItem(":something")
	parseItem(":")
	parseItem("")

	unmarshalSubtreeSpecificationBER(nil)
	parseNot("x")
	parseComplexRefinement("and", "{bogus}")

	bpk := ber.NewSequence(`SubtreeSpecification`)
	unmarshalChopSpecificationBER(bpk)
	unmarshalSubtreeSpecificationBER(bpk)
	unmarshalRefinementNotBER(bpk)
	unmarshalSetRefinementBER(bpk)
	unmarshalRefinementItemBER(bpk)
	bpk.Children = []*ber.Packet{ber.NewSequence("bogus")}
	unmarshalRefinementBER(bpk)
	unmarshalExclusionBER(bpk)
	unmarshalChopSpecificationBER(bpk)
	bpk.Children[0].Value = struct{}{}
	bpk.Children[0].Tag = 0
	unmarshalSubtreeSpecificationBER(bpk)
	bpk.Children[0].Tag = 989
	unmarshalSubtreeSpecificationBER(bpk)
}
