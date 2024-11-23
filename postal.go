package dirsyn

/*
postal.go contains implementations for various postal and mail constructs.
*/

/*
DeliveryMethod implements [§ 3.3.5 of RFC 4517]:

	DeliveryMethod = pdm *( WSP DOLLAR WSP pdm )
	pdm = "any" / "mhs" / "physical" / "telex" / "teletex" /
	      "g3fax" / "g4fax" / "ia5" / "videotex" / "telephone"

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24	  ; dollar sign ("$")
	WSP     = 0*SPACE ; zero or more " "

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.5 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.5
*/
type DeliveryMethod []string

/*
String returns the string representation of the receiver instance.
*/
func (r DeliveryMethod) String() string {
	return join(r, ` $ `)
}

/*
DeliveryMethod returns an error following an analysis of x in the context
of a [DeliveryMethod].
*/
func (r RFC4517) DeliveryMethod(x any) (dm DeliveryMethod, err error) {
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
	var dms DeliveryMethod
	if raw, err = assertString(x, 3, "Delivery Method"); err == nil {
		raws := split(repAll(raw, ` `, ``), `$`)
		for i := 0; i < len(raws) && err == nil; i++ {
			if !strInSlice(raws[i], postalDeliveryMethods) {
				err = errorTxt("Invalid PDM type for Delivery Method: " + raws[i])
			} else {
				dms = append(dms, raws[i])
			}
		}
	}

	if err == nil {
		dm = dms
	}

	return
}

/*
PostalAddress implements the PostalAddress definition per [§ 3.3.28 of
RFC 4517]:

	PostalAddress = line *( DOLLAR line )
	line          = 1*line-char
	line-char     = %x00-23
	                / (%x5C "24")  ; escaped "$"
	                / %x25-5B
	                / (%x5C "5C")  ; escaped "\"
	                / %x5D-7F
	                / UTFMB

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24	  ; dollar sign ("$")
	UTFMB   = UTF2 / UTF3 / UTF4
	UTF0    = %x80-BF
	UTF1    = %x00-7F
	UTF2    = %xC2-DF UTF0
	UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
	          %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
	          %xF4 %x80-8F 2(UTF0)

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.28 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.28
*/
type PostalAddress []string

/*
String returns the string representation of the receiver instance.
*/
func (r PostalAddress) String() string {
	return join(r, `$`)
}

/*
PostalAddress returns an error following an analysis of x in the context
of a [PostalAddress].
*/
func (r RFC4517) PostalAddress(x any) (pa PostalAddress, err error) {
	var lc []string

	var raw string
	if raw, err = assertString(x, 1, "line-char"); err == nil {
		if lc, err = lineChar(raw); err == nil {
			pa = PostalAddress(lc)
		}
	}

	return
}

/*
OtherMailbox implements [§ 3.3.27 of RFC 4517]:

	OtherMailbox = mailbox-type DOLLAR mailbox
	mailbox-type = PrintableString
	mailbox      = IA5String
	IA5String    = *(%x00-7F)

From [§ 1.4 of RFC 4512]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

	ALPHA   = %x41-5A / %x61-7A    ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT        ; "0"-"9"
	SQUOTE  = %x27                 ; single quote ("'")
	SPACE   = %x20                 ; space (" ")
	LPAREN  = %x28                 ; left paren ("(")
	RPAREN  = %x29                 ; right paren (")")
	PLUS    = %x2B                 ; plus sign ("+")
	COMMA   = %x2C                 ; comma (",")
	HYPHEN  = %x2D                 ; hyphen ("-")
	DOT     = %x2E                 ; period (".")
	EQUALS  = %x3D                 ; equals sign ("=")
	DOLLAR  = %x24	               ; dollar sign ("$")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 3.3.27 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.27
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type OtherMailbox [2]string

/*
OtherMailbox returns an error following an analysis of x in the context
of an [OtherMailbox].
*/
func (r RFC4517) OtherMailbox(x any) (om OtherMailbox, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Other Mailbox"); err == nil {
		raws := splitUnescaped(raw, `$`, `\`)

		if len(raws) != 2 {
			err = errorTxt("Invalid Other Mailbox value")
			return
		}

		if _, err = r.PrintableString(raws[0]); err == nil {
			if _, err = r.IA5String(raws[1]); err == nil {
				om[0] = raws[0]
				om[1] = raws[1]
			}
		}
	}

	return
}

func pSOrIA5s(x any) (psia5 []string, err error) {
	sep := `$`
	esc := `\`

	var raw string
	if raw, err = assertString(x, 1, "PrintableString OR IA5String"); err != nil {
		return
	}

	raws := splitUnescaped(raw, sep, esc)
	if len(raws) == 0 {
		err = errorTxt("No values found for PrintableString/IA5 postal address")
		return
	}

	var r RFC4517

	if _, err = r.PrintableString(raws[0]); err != nil {
		return
	}
	psia5 = append(psia5, raws[0])

	for i := 1; i < len(raws); i++ {
		if _, err = r.PrintableString(raws[i]); err == nil {
			psia5 = append(psia5, raws[i])
			continue
		} else if _, err = r.IA5String(raws[i]); err == nil {
			psia5 = append(psia5, raws[i])
			continue
		}
		break
	}

	return
}

func lineChar(raw string) (lineChars []string, err error) {
	var last rune
	value := newStrBuilder()
	for _, r := range raw {
		rL := runeLen(r)
		if rL == 1 {
			// UTF0
			if r == '\\' {
				last = r
				continue
			} else if r == '$' {
				if last == r {
					err = errorTxt("Contiguous '$' runes; invalid line-char sequence")
					break
				} else if last == '\\' {
					value.WriteString(string(last))
					value.WriteString(string(r))
					last = rune(0)
				} else {
					lineChars = append(lineChars, value.String())
					value.Reset()
					last = '$'
				}
				continue
			}

			last = r
			if ucIs(lineCharRange, r) {
				value.WriteString(string(r))
				continue
			} else if err = uTFMB(r); err == nil {
				value.WriteString(string(r))
				continue
			}

			break
		}

		err = errorTxt("Incompatible rune length for UTF0 (in line-char): " + fmtInt(int64(rL), 10))
		break
	}

	if value.Len() > 0 && err == nil {
		lineChars = append(lineChars, value.String())
	}

	return
}
