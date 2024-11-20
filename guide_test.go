package dirsyn

import (
	"testing"
)

func TestEnhancedGuide(t *testing.T) {
	var r RFC4517

	for idx, raw := range []string{
		`account#!(?true&?false)|?true#wholeSubtree`,
		`person#((2.5.4.3$EQ&!2.5.4.3$EQ)|?false)#oneLevel`,
	} {
		if _, err := r.EnhancedGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestGuide(t *testing.T) {
	var r RFC4517

	for idx, raw := range []string{
		`account#!(?true&?false)|?true`,
		`((2.5.4.3$EQ&!2.5.4.7$EQ)|?false)`,
	} {
		if _, err := r.Guide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
