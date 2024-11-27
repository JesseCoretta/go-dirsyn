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

func ExampleOctetString_IsZero() {
	var oct OctetString
	fmt.Println(oct.IsZero())
	// Output: true
}

func ExampleTeletexString_IsZero() {
	var tel TeletexString
	fmt.Println(tel.IsZero())
	// Output: true
}

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
		}
	}
}

func TestBMPString(t *testing.T) {
	var r X680

	results := []string{
		"Σ",
		"HELLO",
		"ABC",
		"HELΣLO",
		"",
	}

	for idx, encoded := range []BMPString{
		{0x1e, 0x1, 0x3, 0xa3}, // sigma Σ
		{0x1e, 0x5, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x0, 0x4c, 0x0, 0x4f},            // HELLO
		{0x1e, 0x3, 0x0, 0x41, 0x0, 0x42, 0x0, 0x43},                                  // ABC
		{0x1e, 0x6, 0x0, 0x48, 0x0, 0x45, 0x0, 0x4c, 0x3, 0xa3, 0x0, 0x4c, 0x0, 0x4f}, // HELΣLO
		{0x1e, 0x0}, // empty
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

func TestUniversalString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`平仮名`,
		`This is a UniversalString.`,
		`This is@~@@~~~ not UniversalString ﺝﺦتﺣﺛrOH WAIT yes it is`,
	} {
		if _, err := r.UniversalString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
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

	octet1 := OctetString{0x01, 0x02, 0x03}
	octet2 := OctetString{0x01, 0x02, 0x02}
	result, err := octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: true\ngot:  %s", t.Name(), result)
		return
	}

	octet1 = OctetString{0x01, 0x02, 0x02}
	result, err = octetStringMatch(octet1, octet2)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.True() {
		t.Errorf("%s failed:\nwant: true\ngot:  %s", t.Name(), result)
	}
}

func TestCountryString(t *testing.T) {
	var r RFC4517

	for _, raw := range []string{
		`US`,
		`CA`,
		`UK`,
		`JP`,
	} {
		if cs, err := r.CountryString(raw); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		} else if got := cs.String(); raw != got {
			t.Errorf("%s failed:\nwant: %s\ngot:  %s",
				t.Name(), raw, got)
		}
	}

	r.CountryString(nil)
	r.CountryString([]byte{})
	r.CountryString(``)
}

func TestBitString(t *testing.T) {
	var r RFC4517

	var raw string = `'10100101'B`
	bs, err := r.BitString(raw)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if got := bs.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
	}
	if bs.IsZero() {
		t.Errorf("%s failed: instance is zero", t.Name())
	}
}

func TestIA5String(t *testing.T) {
	var r RFC4517

	var raw string = `Jerry. Hello.`
	if ia, err := r.IA5String(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if got := ia.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
	}
}

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
}

/*
   BMPString{0x1E, 0x01, 0xDC, 0x00}, // bad
   BMPString{0x00, 0x00, 0xD8, 0x00}, // bad
   BMPString{0x4E, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0xE9}, // bad
   BMPString{0x00, 0x00, 0x00}, // bad
   BMPString{0xFF}, // bad
   PrintableString("Invalid@Chars"), // bad
   PrintableString("Test@PRINTABLE#"), // bad
   PrintableString(""), // bad
   UniversalString("\x00\x00\x00\x20\x00\xDC\x00\x00"), // bad
   UniversalString("\x00\x00\xD8\x00\x00\x00\xDF\xFF"), // bad
   UTF8String("\xC3\x28"), // bad
   UTF8String("\xF0\x28\x8C\xBC"), // bad
   UTF8String("\xF0"), // bad
   UTF8String("\xF0\x82\x82\xAC"), // bad
   UTF8String("\xE2\x28\xA1"), // bad
   TeletexString("\x80\x81\x82"), // bad
   TeletexString("\xC0\xC1"), // bad
   TeletexString("\xF1\xF2\xF3"), // bad
*/

func TestString_codecov(t *testing.T) {
	var r RFC4517
	var s RFC4512
	var x X680

	for _, ds := range []DirectoryString{
		BMPString{0x1E, 0x02, 0x03, 0xA3},
		BMPString{0x1E, 0x06, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43},
		BMPString{0x1E, 0x0a, 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F},
		BMPString{0x1E, 0x08, 0x00, 0x54, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74},
		BMPString{},
		PrintableString(" "),
		PrintableString("Printable123"),
		PrintableString("Yes."),
		UniversalString("こんにちは世界！"),
		UniversalString("This is a universal string 😊"),
		UTF8String(""),
		UTF8String(`ZFKJ345325^&*$`),
		UTF8String("Hola! こんにちは"),
		UTF8String("Hello, 世界!"),
		UTF8String("Zǹǹêrī!"),
		TeletexString(`maybe`),
		TeletexString("Hello"),
		TeletexString("Teletex123!"),
	} {
		_ = ds.String()
		ds.IsZero()
		ds.Choice()
		ds.isDirectoryString()
	}

	//_, _ = r.assertBitString([]byte{})
	//_, _ = r.assertBitString(nil)
	_, _ = verifyBitStringContents([]byte(`'01001011`))
	_, _ = verifyBitStringContents([]byte(`''B`))
	_, _ = verifyBitStringContents([]byte(`01001011'B`))
	_, _ = verifyBitStringContents([]byte(`'0100F011'B`))
	var cs CountryString
	cs.IsZero()
	_ = cs.String()

	isT61Single('\u009B')

	r.CountryString(``)
	r.CountryString(`#@`)

	r.DirectoryString('\u0071')

	raw := `8392810954`

	_, _ = r.UniversalString(nil)
	_, _ = r.IA5String(nil)
	_, _ = s.UTF8String(raw)
	_, _ = s.UTF8String(nil)
	_, _ = r.UniversalString(raw)
	_, _ = x.BMPString(raw)
	_, _ = x.BMPString(`12`)
	_, _ = x.BMPString(nil)
	_, _ = x.BMPString(BMPString([]byte{0x1E, 0x00}))
	_, _ = x.BMPString(BMPString([]byte{0x00, 0x1E}))

	var bigBMP []byte = []byte{0x1E, 0xFF}
	for i := 0; i < 256; i++ {
		bigBMP = append(bigBMP, byte(i))
	}
	_, _ = x.BMPString(bigBMP)
	_, _ = r.UniversalString(``)
	_, _ = r.UniversalString(UniversalString(`XYZ`))
	_, _ = r.UniversalString([]byte{})
	_, _ = r.OctetString([]byte{})
	_, _ = r.OctetString(``)
	_, _ = r.OctetString(nil)
	_, _ = r.TeletexString(``)
	_, _ = r.PrintableString(``)
	_, _ = r.TeletexString(`A`)
	_, _ = r.PrintableString(struct{}{})
	_, _ = r.PrintableString(`A`)
	_, _ = r.TeletexString([]byte(`A`))
	_, _ = r.TeletexString(nil)
	_, _ = r.PrintableString([]byte(`A`))

	var tel TeletexString
	_ = tel.String()
	tel.IsZero()

	var prs PrintableString
	prs.IsZero()
	_ = prs.String()

	_, _ = assertNumericString(`X`)
	_, _ = assertNumericString(``)
	_, _ = assertNumericString(nil)
	_, _ = assertNumericString(uint(0))
	_, _ = assertNumericString(int32(-1))
	_, _ = assertNumericString(uint16(0))

	var ns NumericString
	_ = ns.String()
	ns.IsZero()

	var us UniversalString
	_ = us.String()
	us.IsZero()
}
