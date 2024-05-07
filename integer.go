package dirsyn

/*
Integer returns an error following an analysis of x in the context of
an ASN.1 Integer.

From § 3.3.16 of RFC 4517:

	Integer = ( HYPHEN LDIGIT *DIGIT ) / number
*/
func (r RFC4517) Integer(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Integer", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Integer")
		return
	}

	// discard leading dash if present.
	if raw[0] == '-' {
		raw = raw[1:]
	}

	// fail if value is greater than one (1) character in
	// length AND if leading digit is zero (0).  Integers
	// are not octals.
	if len(raw) > 1 && rune(raw[0]) == '0' {
		err = errorTxt("Octal value incompatible with integer")
		return
	}

	for _, ch := range raw {
		if !isDigit(rune(ch)) {
			err = errorTxt("Non digit character incompatible with integer: " + string(ch))
			break
		}
	}

	return
}
