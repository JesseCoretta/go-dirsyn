package dirsyn

import (
	"fmt"
	"testing"
)

func ExampleOctetString_IsZero() {
	var oct OctetString
	fmt.Println(oct.IsZero())
	// Output: true
}

func TestOctetString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		``,
		`This is an OctetString.`,
	} {
		if oct, err := r.OctetString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := oct.String(); raw != got {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}

	octet1 := OctetString{0x01, 0x02, 0x02}
	octet2 := OctetString{0x01, 0x02, 0x02}
	result, err := octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %s", t.Name(), result)
	}

	octet1 = OctetString{0x01, 0x02, 0x03}
	result, err = octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %s", t.Name(), result)
		return
	}

	result, err = octetStringOrderingMatch(octet1, octet2, GreaterOrEqual)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: TRUE\ngot:  %s", t.Name(), result)
	}

	_, _ = octetStringMatch([]byte{}, []byte{})
	_, _ = octetStringMatch([]byte{}, struct{}{})
	_, _ = octetStringMatch(struct{}{}, []byte{})
	_, _ = octetStringMatch([]byte{}, []byte{0x0})
	_, _ = octetStringMatch([]byte{0x0}, []byte{})

	_, _ = octetStringOrderingMatch([]byte{}, []byte{}, LessOrEqual)
	_, _ = octetStringOrderingMatch([]byte{}, struct{}{}, LessOrEqual)
	_, _ = octetStringOrderingMatch(struct{}{}, []byte{}, LessOrEqual)
	_, _ = octetStringOrderingMatch([]byte{0x0}, []byte{0x1, 0x2}, LessOrEqual)
	_, _ = octetStringOrderingMatch([]byte{0x1}, []byte{}, LessOrEqual)

	_ = octetString([]byte{})
	_ = octetString([]byte{0x0, 0x1, 0x2})
}
