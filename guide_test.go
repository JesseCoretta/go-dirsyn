package dirsyn

import (
	"testing"
)

func TestEnhancedGuide(t *testing.T) {
	var r RFC4517

	for idx, raw := range []string{
		`account#!(?true&?false&2.5.4.0$EQ)|?true#wholeSubtree`,
		`person#((2.5.4.3$GE&!2.5.4.3$SUBSTR)|?false)#oneLevel`,
	} {
		if g, err := r.EnhancedGuide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := g.String(); raw != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s", t.Name(), idx, raw, got)
		}
	}
}

func TestGuide(t *testing.T) {
	var r RFC4517

	for idx, raw := range []string{
		`account#!(?true&?false)|?true`,
		`((2.5.4.3$SUBSTR&!(2.5.4.7$LE&2.5.4.0$APPROX))|?false)`,
	} {
		if g, err := r.Guide(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := g.String(); raw != got {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s", t.Name(), idx, raw, got)
		}
	}
}

func TestGuide_codecov(t *testing.T) {
	var amt AttributeMatchTerm
	amt.IsZero()
	_ = amt.String()

	var bt BoolTerm
	bt.IsZero()
	_ = bt.String()

	var at AndTerm
	at.IsZero()
	_ = at.String()
	at.Paren = true
	_ = at.String()

	var r RFC4517
	for _, bogus := range []any{
		``,
		nil,
		`account#values`,
		`___#baseOb`,
		`___#baseOb#...`,
		`___#:::::::#...`,
		`#baseObject`,
		`yo#()#1`,
		`account##baseObject`,
		`account#Jerry.Hello#baseObject`,
	} {
		g, _ := r.Guide(bogus)
		_ = g.String()
		eg, _ := r.EnhancedGuide(bogus)
		_ = eg.String()
	}

	subsetToInt(`baseobject`)
	subsetToInt(`onelevel`)
	subsetToInt(`wholesubtree`)

	intToSubset(0)
	intToSubset(1)
	intToSubset(2)
}
