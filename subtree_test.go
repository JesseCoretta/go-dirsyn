package dirsyn

import "testing"

func TestSubtreeSpecification(t *testing.T) {
	var r RFC3672

	for idx, raw := range []string{
		`{ base 'n=1,n=4,n=1,n=6,n=3,n=1', minimum 1, maximum 1, specificationFilter and:{item:1.3.6.1.4.1,or:{item:cn,item:2.5.4.7}} }`,
		`{ base 'n=1,n=4,n=1,n=6,n=3,n=1', minimum 1, maximum 1, specificationFilter item:1.3.6.1.4.1.56521 }`,
	} {
		if _, err := r.SubtreeSpecification(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
