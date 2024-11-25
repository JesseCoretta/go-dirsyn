package dirsyn

import (
	"testing"
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

	var spec SubtreeSpecification
	spec.BER()
	_ = spec.String()

	var chop ChopSpecification
	chop.BER()

	var orref OrRefinement
	orref.BER()
	_ = orref.String()
	orref.Index(2)
	orref.isRefinement()

	var andref AndRefinement
	andref.BER()
	_ = andref.String()
	andref.Index(2)
	andref.isRefinement()

	var excls SpecificExclusions
	excls.BER()
	_ = excls.String()

	var excl SpecificExclusion
	excl.BER()
	_ = excl.String()

	var iref ItemRefinement
	iref.BER()
	iref.Choice()
	_ = iref.String()
	iref.Len()
	iref.Index(1)
	iref.isRefinement()

	var nref NotRefinement
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
}
