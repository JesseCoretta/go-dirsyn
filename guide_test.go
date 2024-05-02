package dirsyn

import (
	"testing"
)

func TestEnhancedGuide(t *testing.T) {
	for idx, raw := range []string{
		`account#!(?true&?false)|?true#wholeSubtree`,
		`person#((2.5.4.3$EQ&!2.5.4.3$EQ)|?false)#oneLevel`,
	} {
		if err := EnhancedGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestGuide(t *testing.T) {
	for idx, raw := range []string{
		`account#!(?true&?false)|?true`,
		`((2.5.4.3$EQ&!2.5.4.7$EQ)|?false)`,
	} {
		if err := Guide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
