package dirsyn

import (
	"testing"
)

func TestPrintableString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`WAT`,
		`This is a printable string.`,
	} {
		if _, err := r.PrintableString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}

	_, _ = marshalPrintableString(`&1.555.123.4567`)
	_, _ = marshalPrintableString(`&1.555👩123.4567`)

}
