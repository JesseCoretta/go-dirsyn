package dirsyn

import "testing"

func TestSubtreeSpecification(t *testing.T) {
	var r RFC3672

	// Verify parsing of valid string-based SubSpec values
	for idx, raw := range []string{
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter and:{item:1.3.6.1.4.1,or:{item:cn,item:2.5.4.7}}}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter and:{item:1.3.6.1.4.1,not:item:1.3.6.1.5.5,or:{item:cn,item:2.5.4.7}}}`,
		`{base "n=1,n=4,n=1,n=6,n=3,n=1", minimum 1, maximum 1, specificationFilter item:1.3.6.1.4.1.56521}`,
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
		}
	}
}
