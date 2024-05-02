package dirsyn

import (
	"testing"
)

func TestSubstringAssertion(t *testing.T) {
	for idx, raw := range []string{
		`substring*substring`,
		`substri\\\\n*stringy`,
		`*substring*substring*`,
		`substr\\\\*ing*end`,
		`substring*substring*substring`,
		`substr\\*ing*end`,
	} {
		if err := SubstringAssertion(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestUUID(t *testing.T) {
	for idx, raw := range []string{
		`f81d4fae-7dec-11d0-a765-00a0c91e6bf6`,
	} {
		if err := UUID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
