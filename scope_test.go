package dirsyn

import (
	"testing"
)

func TestSearchScope(t *testing.T) {
	tests := []struct {
		Scope any
		Valid bool
	}{
		{
			Scope: 0,
			Valid: true,
		},
		{
			Scope: 1,
			Valid: true,
		},
		{
			Scope: "baseObject",
			Valid: true,
		},
		{
			Scope: 1,
			Valid: true,
		},
		{
			Scope: "onelevel",
			Valid: true,
		},
		{
			Scope: 2,
			Valid: true,
		},
		{
			Scope: "subtree",
			Valid: true,
		},
		{
			Scope: 4,
		},
		{
			Scope: "onelivel",
		},
	}

	var r RFC4511
	for idx, obj := range tests {
		s, err := r.SearchScope(obj.Scope)
		if obj.Valid {
			if err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
				return
			} else if s.String() == badSearchScope {
				t.Errorf("%s[%d] failed: bogus scope", t.Name(), idx)
				return
			}
		} else if err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		}
	}
}
