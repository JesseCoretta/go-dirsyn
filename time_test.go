package dirsyn

import (
	"testing"
	"time"
)

func TestUTCTime(t *testing.T) {
	var r RFC4517

	for idx, thyme := range []string{
		`9805061703Z`,
		`980506170306Z`,
		`620506170306-0500`,
	} {
		if utct, err := r.UTCTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = utct.String()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`98170306Z`,
	} {
		if utct, err := r.UTCTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		} else {
			utct.Eq(nil)
			utct.Ne(nil)
			utct.Gt(nil)
			utct.Ge(nil)
			utct.Lt(nil)
			utct.Le(nil)
			timeMatch(utct, utct, 1)
		}
	}
}

func TestGeneralizedTime(t *testing.T) {
	var r RFC4517

	for idx, thyme := range []string{
		`20240229155701.0Z`,
		`20240229155703.00Z`,
		`20240229155702.000Z`,
		`20240229155703.0000Z`,
		`20240229155703.00000Z`,
		`20240229155703.000000Z`,
		`19540426135103Z`,
		`20240229155703-0500`,
		`20240229155703.0-0700`,
		`20240229155703.00-0700`,
		`20240229155703.000+1100`,
		`20240229155703.0000-0200`,
		`20240229155703.00000-0800`,
		`20200629155703.000000-0100`,
	} {
		if thyme, err := r.GeneralizedTime(thyme); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			_ = thyme.String()
		}
	}

	for idx, thyme := range []any{
		`20`,
		20,
		`F`,
		`00Z`,
		rune(10),
		struct{}{},
		`202402291550.0000000-0800`,
		`20241202183734.0000000-0700`,
	} {
		if _, err := r.GeneralizedTime(thyme); err == nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
			return
		}
	}

	_, err := genTimeFracDiffFormat(`20241202183734Z`, `.00000000`, `-0700`, `20060102150405`)
	if err == nil {
		t.Errorf("%s failed: expected error, got nil", t.Name())
	}
}

func TestGeneralizedTimeMatchingRules(t *testing.T) {
	assertions := map[int]string{
		-1: `negatedEqualityMatch`,
		0:  `equalityMatch`,
		1:  `greaterOrEqual`,
		2:  `lessOrEqual`,
		3:  `greaterThan`,
		4:  `lessThan`,
	}

	type assertion struct {
		A, B any
		T    int
		R    [4]bool
	}

	var r RFC4517

	var err error
	for idx, try := range []assertion{
		{A: `20250408193455.013845Z`, B: `20230408193455Z`, T: -1, R: [4]bool{true, true, true, true}},
		{A: `20250408193455Z`, B: `20250408193455Z`, T: 0, R: [4]bool{true, true, true, true}},
		{A: `20250408193455Z`, B: `20240101000001.163742-0700`, T: 1, R: [4]bool{true, false, true, true}},
		{A: `20210408193455Z`, B: `20240101000001.163742-0700`, T: 2, R: [4]bool{true, false, true, true}},
		{A: `20250408193455Z`, B: `20240101000001.163742-0700`, T: 3, R: [4]bool{true, false, true, true}},
		{A: `20210408193455Z`, B: `20240101000001.163742-0700`, T: 4, R: [4]bool{true, false, true, true}},
	} {
		var A, B GeneralizedTime
		if A, err = r.GeneralizedTime(try.A); err != nil {
			t.Errorf("%s[%d] parse failed: %v", t.Name(), idx, err)
			continue
		}
		if B, err = r.GeneralizedTime(try.B); err != nil {
			t.Errorf("%s[%d] parse failed: %v", t.Name(), idx, err)
			continue
		}

		AT := time.Time(A)
		BT := time.Time(B)

		var results []bool = make([]bool, len(try.R), len(try.R))
		switch try.T {
		case -1:
			results[0] = try.R[0] == A.Ne(BT)
			results[1] = try.R[1] == B.Ne(AT)
			results[2] = try.R[2] == A.Ne(B)
			results[3] = try.R[3] == A.Ne(B.String())
		case 0:
			results[0] = try.R[0] == A.Eq(BT)
			results[1] = try.R[1] == B.Eq(AT)
			results[2] = try.R[2] == A.Eq(B)
			results[3] = try.R[3] == A.Eq(B.String())
		case 1:
			results[0] = try.R[0] == A.Ge(BT)
			results[1] = try.R[1] == B.Ge(AT)
			results[2] = try.R[2] == A.Ge(B)
			results[3] = try.R[3] == A.Ge(B.String())
		case 2:
			results[0] = try.R[0] == A.Le(BT)
			results[1] = try.R[1] == B.Le(AT)
			results[2] = try.R[2] == A.Le(B)
			results[3] = try.R[3] == A.Le(B.String())
		case 3:
			results[0] = try.R[0] == A.Gt(BT)
			results[1] = try.R[1] == B.Gt(AT)
			results[2] = try.R[2] == A.Gt(B)
			results[3] = try.R[3] == A.Gt(B.String())
		case 4:
			results[0] = try.R[0] == A.Lt(BT)
			results[1] = try.R[1] == B.Lt(AT)
			results[2] = try.R[2] == A.Lt(B)
			results[3] = try.R[3] == A.Lt(B.String())
		}

		for idx2, res := range results {
			if !res {
				t.Errorf("%s[%d] %s failed [gen time]:\nwant: %t\ngot:  %t",
					t.Name(), idx, assertions[idx], try.R[idx2], res)
			}
		}
	}
}
