package dirsyn

/*
IA5String implements [§ 3.2 of RFC 4517]:

	IA5 = 0x0000 through 0x00FF

[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
*/
type IA5String string

/*
String returns the string representation of the receiver instance.
*/
func (r IA5String) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r IA5String) IsZero() bool { return len(r) == 0 }

/*
IA5String returns an instance of [IA5String] alongside an error following
an analysis of x in the context of an IA5 String.
*/
func (r RFC4517) IA5String(x any) (ia5 IA5String, err error) {
	return marshalIA5String(x)
}

func iA5String(x any) (result Boolean) {
	_, err := marshalIA5String(x)
	result.Set(err == nil)
	return
}

func marshalIA5String(x any) (ia5 IA5String, err error) {
	var raw string
	if raw, err = assertString(x, 1, "IA5String"); err == nil {
		if err = checkIA5String(raw); err == nil {
			ia5 = IA5String(raw)
		}
	}

	return
}

func checkIA5String(raw string) (err error) {
	if len(raw) == 0 {
		err = errorTxt("Invalid IA5 String (zero)")
		return
	}

	for i := 0; i < len(raw) && err == nil; i++ {
		var char rune = rune(raw[i])
		if !ucIs(iA5Range, char) {
			err = errorTxt("Invalid IA5 String character: " + string(char))
		}
	}

	return
}

func caseExactIA5Match(a, b any) (Boolean, error) {
	return caseBasedIA5Match(a, b, true)
}

func caseIgnoreIA5Match(a, b any) (Boolean, error) {
	return caseBasedIA5Match(a, b, false)
}

func caseBasedIA5Match(a, b any, caseExact bool) (result Boolean, err error) {
	var str1, str2 string
	if str1, err = assertString(a, 1, "ia5String"); err != nil {
		return
	}

	if str2, err = assertString(b, 1, "ia5String"); err != nil {
		return
	}

	result.Set(false)
	if err = checkIA5String(str1); err == nil {
		if err = checkIA5String(str2); err == nil {
			if caseExact {
				result.Set(streq(str1, str2))
			} else {
				result.Set(streqf(str1, str2))
			}
		}
	}

	return
}

func prepareIA5StringAssertion(a, b any) (str1, str2 string, err error) {
	assertIA5 := func(x any) (i string, err error) {
		var raw string
		if raw, err = assertString(x, 1, "IA5String"); err == nil {
			if err = checkIA5String(raw); err == nil {
				i = raw
			}
		}
		return
	}

	if str1, err = assertIA5(a); err == nil {
		str2, err = assertIA5(b)
	}

	return
}

func caseIgnoreIA5SubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareIA5StringAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}
