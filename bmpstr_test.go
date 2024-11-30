package dirsyn

import (
	"fmt"
	"testing"
)

func ExampleBMPString_IsZero() {
	var bmp BMPString
	fmt.Println(bmp.IsZero())
	// Output: true
}

func TestBMPString(t *testing.T) {
	var r X680

	results := []string{
		"Σ",
		"HELLO",
		"ABC",
		"HELΣLO",
		"",
		"",
	}

	for idx, encoded := range []BMPString{
		{0x1e, 0x1, 0x3, 0xa3}, // sigma Σ
		{0x1e, 0x5, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x0, 0x4c, 0x0, 0x4f},            // HELLO
		{0x1e, 0x3, 0x0, 0x41, 0x0, 0x42, 0x0, 0x43},                                  // ABC
		{0x1e, 0x6, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x3, 0xa3, 0x0, 0x4c, 0x0, 0x4f}, // HELΣLO
		{0x1e, 0x0}, // empty-ish
		{},          // really empty
	} {
		if decoded := encoded.String(); decoded != results[idx] {
			t.Errorf("%s[%d] stringer failed:\nwant: %#v\ngot:  %#v",
				t.Name(), idx, results[idx], decoded)
		}
	}

	for idx, decoded := range results {
		if encoded, err := r.BMPString(decoded); err != nil {
			t.Errorf("ENCODE: %s[%d] failed: %v",
				t.Name(), idx, err)
		} else if reenc := encoded.String(); reenc != results[idx] {
			t.Errorf("ENCODE: %s[%d] failed:\nwant:%#v [%d]\ngot: %#v [%d]",
				t.Name(), idx, decoded, len(decoded),
				results[idx], len(results[idx]))
		}
	}
}

func TestBMPString_codecov(t *testing.T) {
	assertBMPString(BMPString{})
	assertBMPString(BMPString{0x1e, 0x1, 0x1, 0xef})
	assertBMPString(BMPString{0x1a, 0x1, 0x1, 0xef})
}
