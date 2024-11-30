package dirsyn

import (
	"testing"
)

func TestList(t *testing.T) {
	result, err := caseIgnoreListMatch(
		[]string{
			`this`, `is`, `a`, `list`,
		},
		[]string{
			`this`, `is`, `a`, `list`,
		})

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
	}

	result, err = caseIgnoreListMatch(
		[]string{
			`this`, `iz`, `a`, `list`,
		},
		[]string{
			`this`, `is`, `a`, `list`,
		})

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), `FALSE`, result)
	}

	_, _ = caseIgnoreListMatch(nil, nil)
	_, _ = caseIgnoreListMatch([]string{}, nil)
	_, _ = caseIgnoreListMatch([]string{}, []string{`a`})
	_, _ = caseIgnoreListMatch(nil, struct{}{})
	_, _ = caseIgnoreListMatch(struct{}{}, nil)
}
