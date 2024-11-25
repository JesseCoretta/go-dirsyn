package dirsyn

/*
JPEG returns an error following an analysis of x in the context of a JFIF
enveloped payload, which resembles the following:

	                      +- NULL (CTRL+@)
	                     /  +- DATA LINK ESCAPE (CTRL+P)
	                    /  /  +- ENVELOPE LITERAL
	                   +  +   |
	       ÿ  Ø  ÿ  à  |  |   |                         ÿ  Ù
	      -- -- -- -- -- -- ----                       -- --
	<SOF> FF D8 FF 0E 00 10 JFIF <variable image data> FF D9 <EOF>

Note that only the envelope elements -- specifically the header and footer --
are read. Actual image data is skipped for performance reasons.

Valid input values are string and []byte.

If the input value is a string, it is assumed the value leads to a path
and filename of a JPEG image file.

If the input value is a []byte instance, it may be raw JPEG data, or Base64
encoded JPEG data. If Base64 encoded, it is decoded and processed.

All other input types result in an error.

Aside from the error instance, there is no return type for parsed JPEG
content, as this would not serve any useful purpose to end users in any
of the intended use cases for this package.

See also [§ 3.3.17 of RFC 4517].

[§ 3.3.17 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.17
*/
func (r RFC4517) JPEG(x any) (err error) {
	var raw []uint8

	switch tv := x.(type) {
	case string:
		// Read from file
		if raw, err = readFile(tv); err == nil {
			// Self-execute using the byte payload
			err = r.JPEG(raw)
			return
		}
	case []uint8:
		if len(tv) <= 12 {
			err = errorBadLength("JPEG", len(tv))
		} else {
			if isBase64(string(tv)) {
				var dec []byte
				dec, err = b64dec(tv)
				raw = dec
			} else {
				raw = tv
			}
		}
	default:
		err = errorBadType("JPEG")
	}

	if err != nil {
		return
	}

	header := []rune{
		'\u00FF',
		'\u00D8',
		'\u00FF',
		'\u00E0',
		'\u0000',
		'\u0010',
		'J',
		'F',
		'I',
		'F',
	}

	for idx, h := range header {
		if h != rune(raw[idx]) {
			err = errorTxt("Incompatible character for JPEG header: " + string(h))
			return
		}
	}

	footer := []rune{
		'\u00FF', // len-2
		'\u00D9', // len-1
	}

	if rune(raw[len(raw)-2]) != footer[0] ||
		rune(raw[len(raw)-1]) != footer[1] {
		err = errorTxt("Incompatible character for JPEG footer: " + string(raw[len(raw)-2:]))
	}

	return
}
