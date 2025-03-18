package dirsyn

import (
	"testing"
)

func TestNumericString(t *testing.T) {
	var r RFC4517

	for _, raw := range []any{
		`01 37 3748`,
		483982,
		`483982`,
		0,
		`00 00 00000000000000`,
	} {
		if ns, err := r.NumericString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else {
			_ = ns.String()
			if !numericString(raw).True() {
				t.Errorf("%s failed: failed to parse numericString", t.Name())
			}
		}
	}

	marshalNumericString(`ABC`)
}

func TestNumericString_SubstringsMatch(t *testing.T) {
	result, err := numericStringSubstringsMatch(`48 129 647`, `48*12* 6*7`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s", t.Name(), `TRUE`, result)
	}
}

func TestNumericString_NumericStringMatch(t *testing.T) {
	result, err := numericStringMatch(`01 37 47`, `013747`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %s", t.Name(), result)
	}
}

func TestNumericString_OrderingMatch(t *testing.T) {
	result, err := numericStringOrderingMatch(`01 47 47`, `01 37 47`, LessOrEqual)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: FALSE\ngot:  %s", t.Name(), result)
	}
}

func TestNumericString_codecov(t *testing.T) {
	_, _, _ = prepareNumericStringAssertion(struct{}{}, `ok`)
	_, _, _ = prepareNumericStringAssertion(`ok`, struct{}{})
}
