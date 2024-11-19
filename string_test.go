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
	if bs, err := r.BitString(raw); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if got := bs.String(); raw != got {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s",
			t.Name(), raw, got)
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

func TestDirectoryString(t *testing.T) {
	var r RFC4517

	for idx, raw := range []any{
		`This is a Directory String.`,
		BMPString{0xD8, 0x00, 0xDC, 0x00}, // bad
		BMPString{0x1E, 0x02, 0x03, 0xA3},
		BMPString{0x00, 0x00, 0xD8, 0x00}, // bad
		BMPString{0x1E, 0x02, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43},
		BMPString{0x4E, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0xE9}, // bad
		BMPString{0x1E, 0x02, 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F},
		BMPString{0x00, 0x00, 0x00}, // bad
		BMPString{0x1E, 0x02, 0x00, 0x54, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74},
		BMPString{0xFF}, // bad
		BMPString{},
		PrintableString("Invalid@Chars"), // bad
		PrintableString(" "),
		PrintableString("Test@PRINTABLE#"), // bad
		PrintableString("Printable123"),
		PrintableString(""), // bad
		PrintableString("Yes."),
		UniversalString("\x00\x00\x00\x20\x00\xDC\x00\x00"), // bad
		UniversalString("こんにちは世界！"),
		UniversalString("\x00\x00\xD8\x00\x00\x00\xDF\xFF"), // bad
		UniversalString("This is a universal string 😊"),
		UTF8String("\xC3\x28"), // bad
		UTF8String(""),
		UTF8String("\xF0\x28\x8C\xBC"), // bad
		UTF8String(`ZFKJ345325^&*$`),
		UTF8String("\xF0"), // bad
		UTF8String("Hola! こんにちは"),
		UTF8String("\xF0\x82\x82\xAC"), // bad
		UTF8String("Hello, 世界!"),
		UTF8String("\xE2\x28\xA1"), // bad
		UTF8String("Zǹǹêrī!"),
		TeletexString("\x80\x81\x82"), // bad
		TeletexString(`maybe`),
		TeletexString("\xC0\xC1"), // bad
		TeletexString("Hello"),
		TeletexString("\xF1\xF2\xF3"), // bad
		TeletexString("Teletex123!"),
	} {
		even := idx%2 == 0
		_, err := r.DirectoryString(raw)
		ok := err == nil
		if !ok && even {
			t.Errorf("%s[%d] %T failed: %v", t.Name(), idx, raw, err)
		} else if ok && !even {
			t.Errorf("%s[%d] %T succeeded but should have failed", t.Name(), idx, raw)
		}
	}
}
