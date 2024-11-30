package dirsyn

/*
CountryString implements [§ 3.3.4 of RFC 4517]:

	CountryString  = 2(PrintableCharacter)

From [§ 1.4 of RFC 4512]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.4 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4
*/
type CountryString string

/*
String returns the string representation of the receiver instance.
*/
func (r CountryString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r CountryString) IsZero() bool { return len(r) == 0 }

func countryString(x any) (result Boolean) {
	_, err := marshalCountryString(x)
	result.Set(err == nil)
	return
}

/*
CountryString returns an error following an analysis of x in the context of
an [ISO 3166] country code. Note that specific codes -- though syntactically
valid -- should be verified periodically in lieu of significant world events.

[ISO 3166]: https://www.iso.org/iso-3166-country-codes.html
*/
func (r RFC4517) CountryString(x any) (CountryString, error) {
	return marshalCountryString(x)
}

func marshalCountryString(x any) (cs CountryString, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) != 2 {
			err = errorBadLength("Country String", 0)
			return
		}
		raw = tv
	case []byte:
		cs, err = marshalCountryString(string(tv))
		return
	default:
		err = errorBadType("Country String")
		return
	}

	if !isUAlpha(rune(raw[0])) || !isUAlpha(rune(raw[1])) {
		err = errorTxt("Incompatible characters for Country String: " +
			string(raw[0]) + "/" + string(raw[0]))
		return
	}

	var mdata []byte
	if mdata, err = asn1m(raw); err == nil {
		var testcss CountryString
		if _, err = asn1um(mdata, &testcss); err == nil {
			if testcss.String() == raw {
				cs = CountryString(raw)
			}
		}
	}

	return
}
