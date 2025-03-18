package dirsyn

/*
NumericString implements [§ 3.3.23 of RFC 4517]:

	NumericString = 1*(DIGIT / SPACE)

[§ 3.3.23 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23
*/
type NumericString string

/*
String returns the string representation of the receiver instance.
*/
func (r NumericString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NumericString) IsZero() bool { return len(r) == 0 }

func numericString(x any) (result Boolean) {
	_, err := marshalNumericString(x)
	result.Set(err == nil)
	return
}

/*
NumericString returns an instance of [NumericString] alongside an error
following an analysis of x in the context of a Numeric String.
*/
func (r RFC4517) NumericString(x any) (NumericString, error) {
	return marshalNumericString(x)
}

func marshalNumericString(x any) (ns NumericString, err error) {
	var raw string
	if raw, err = assertNumericString(x); err == nil {
		for _, char := range raw {
			if !(isDigit(rune(char)) || char == ' ') {
				err = errorTxt("Incompatible character for Numeric String: " + string(char))
				break
			}
		}
	}

	if err == nil {
		ns = NumericString(raw)
	}

	return
}

func assertNumericString(x any) (raw string, err error) {
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		if isNegativeInteger(tv) {
			err = errorTxt("Incompatible sign (-) for Numeric String")
			break
		}
		var cint int64
		if cint, err = castInt64(tv); err == nil {
			raw = fmtInt(cint, 10)
		}
	case uint, uint8, uint16, uint32, uint64:
		var cuint uint64
		if cuint, err = castUint64(tv); err == nil {
			raw = fmtUint(cuint, 10)
		}
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Numeric String", 0)
			break
		}
		raw = tv
	default:
		err = errorBadType("Numeric String")
	}

	return
}

// RFC 4518 § 2.6.2
func prepareNumericStringAssertion(a, b any) (str1, str2 string, err error) {
	if str1, err = assertString(a, 0, "numericString"); err != nil {
		return
	}

	if str2, err = assertString(b, 0, "numericString"); err != nil {
		return
	}

	str1 = repAll(str1, ` `, ``)
	str2 = repAll(str2, ` `, ``)

	return
}

func numericStringMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result.Set(streq(str1, str2))
	}

	return
}

func numericStringOrderingMatch(a, b any, operator byte) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		if operator == GreaterOrEqual {
			result.Set(str1 >= str2)
		} else {
			result.Set(str1 <= str2)
		}
	}

	return
}

func numericStringSubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result, err = caseExactSubstringsMatch(str1, str2)
	}

	return
}
