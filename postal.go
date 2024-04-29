package dirsyn

/*
postal.go contains implementations for various postal and mail constructs.
*/

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

/*
DeliveryMethod returns an error following an analysis of x in the context
of a DeliveryMethod.

From § 3.3.5 of RFC 4517:

	DeliveryMethod = pdm *( WSP DOLLAR WSP pdm )
	pdm = "any" / "mhs" / "physical" / "telex" / "teletex" /
	      "g3fax" / "g4fax" / "ia5" / "videotex" / "telephone"
*/
func DeliveryMethod(x any) (err error) {
	postalDeliveryMethods := []string{
		// Method	ASN.1 Type Integer [X.520]
		`any`,       // 0
		`mhs`,       // 1
		`physical`,  // 2
		`telex`,     // 3
		`teletex`,   // 4
		`g3fax`,     // 5
		`g4fax`,     // 6
		`ia5`,       // 7
		`videotex`,  // 8
		`telephone`, // 9
	}

	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) < 3 {
			err = fmt.Errorf("Zero length or incomplete Delivery Method value")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Delivery Method", tv)
		return
	}

	raws := strings.Split(strings.ReplaceAll(raw, ` `, ``), `$`)
	for i := 0; i < len(raws) && err == nil; i++ {
		if !strInSlice(raws[i], postalDeliveryMethods) {
			err = fmt.Errorf("Invalid PDM type '%s' for Delivery Method", raws[i])
		}
	}

	return
}

/*
PostalAddress returns an error following an analysis of x in the context
of a PostalAddress.

From § 3.3.28 of RFC 4517:

	PostalAddress = line *( DOLLAR line )
	line          = 1*line-char
	line-char     = %x00-23
	                / (%x5C "24")  ; escaped "$"
	                / %x25-5B
	                / (%x5C "5C")  ; escaped "\"
	                / %x5D-7F
	                / UTFMB
*/
func PostalAddress(x any) (err error) {
	for _, err = range []error{
		IA5String(x),
		pSOrIA5s(x),
		lineChar(x),
	} {
		if err == nil {
			break
		}
	}

	return
}

/*
OtherMailbox returns an error following an analysis of x in the context
of an OtherMailbox.

From § 3.3.27 of RFC 4517:

	OtherMailbox = mailbox-type DOLLAR mailbox
	mailbox-type = PrintableString
	mailbox      = IA5String
*/
func OtherMailbox(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Other Mailbox", tv)
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)

	if len(raws) != 2 {
		err = fmt.Errorf("Invalid Other Mailbox value")
		return
	}

	if err = PrintableString(raws[0]); err != nil {
		return
	}
	err = IA5String(raws[1])

	return
}

func pSOrIA5s(x any) (err error) {
	sep := `$`
	esc := `\`

	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for PrintableString postal address", tv)
		return
	}

	raws := splitUnescaped(raw, sep, esc)
	if len(raws) == 0 {
		err = fmt.Errorf("No values found for PrintableString/IA5 postal address")
		return
	}

	if err = PrintableString(raws[0]); err != nil {
		return
	}

	for i := 1; i < len(raws); i++ {
		if err = PrintableString(raws[i]); err == nil {
			continue
		} else if IA5String(raws[i]); err == nil {
			continue
		}
		break
	}

	return
}

func lineChar(x any) (err error) {

	lCRange := &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0023, 1},
		{0x0025, 0x005B, 1},
		{0x005D, 0x007F, 1},
	}}

	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Invalid line-char string")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for line-char", tv)
		return
	}

	var last rune
	for _, r := range raw {
		if runeLength := utf8.RuneLen(r); runeLength == 1 {
			// UTF0
			if r == '\\' {
				last = r
				continue
			} else if r == '$' {
				if last == r {
					err = fmt.Errorf("Contiguous '$' runes; invalid line-char sequence")
					break
				} else if last == '\\' {
					last = rune(0)
				} else {
					last = '$'
				}
				continue
			}

			last = r
			if unicode.Is(lCRange, r) {
				continue
			} else if err = uTFMB(x); err == nil {
				continue
			}

			break
		} else {
			err = fmt.Errorf("Incompatible rune length '%d' for UTF0 (in line-char)", runeLength)
			break
		}
	}

	return
}
