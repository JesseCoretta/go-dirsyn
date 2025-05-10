package dirsyn

/*
SubstringAssertion implements the Substring Assertion.

From [§ 3.3.30 of RFC 4517]:

	SubstringAssertion = [ initial ] any [ final ]

	initial  = substring
	any      = ASTERISK *(substring ASTERISK)
	final    = substring
	ASTERISK = %x2A  ; asterisk ("*")

	substring           = 1*substring-character
	substring-character = %x00-29
	                      / (%x5C "2A")  ; escaped "*"
	                      / %x2B-5B
	                      / (%x5C "5C")  ; escaped "\"
	                      / %x5D-7F
	                      / UTFMB

From [§ 2 of RFC 4515]:

	SubstringFilter ::= SEQUENCE {
	    type    AttributeDescription,
	    -- initial and final can occur at most once
	    substrings    SEQUENCE SIZE (1..MAX) OF substring CHOICE {
	     initial        [0] AssertionValue,
	     any            [1] AssertionValue,
	     final          [2] AssertionValue } }

From [§ 3 of RFC 4515]:

	initial = assertionvalue
	any     = ASTERISK *(assertionvalue ASTERISK)
	final   = assertionvalue

[§ 2 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[§ 3 of RFC 4515]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
[§ 3.3.30 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30
*/
type SubstringAssertion struct {
	Initial AssertionValue `asn1:"tag:0"`
	Any     AssertionValue `asn1:"tag:1"`
	Final   AssertionValue `asn1:"tag:2"`
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r SubstringAssertion) IsZero() bool {
	return len(r.Initial) == 0 &&
		len(r.Any) == 0 &&
		len(r.Final) == 0
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubstringAssertion) String() (s string) {
	Any := func() string {
		if len(r.Any) > 0 {
			return `*` + r.Any.String() + `*`
		}
		return `*`
	}

	if !r.IsZero() {
		bld := newStrBuilder()

		if len(r.Initial) > 0 {
			bld.WriteString(r.Initial.String())
			bld.WriteString(Any())
			if len(r.Final) > 0 {
				bld.WriteString(r.Final.String())
			}
		} else if len(r.Final) > 0 {
			bld.WriteString(Any())
			bld.WriteString(r.Final.String())
		} else {
			// If a star is the only value,
			// don't save anything.
			bld.WriteString(Any())
		}

		s = bld.String()
	}

	return
}

/*
SubstringAssertion returns an error following an analysis of x in the
context of a Substring Assertion.
*/
func (r RFC4517) SubstringAssertion(x any) (SubstringAssertion, error) {
	return marshalSubstringAssertion(x)
}

func substringAssertion(x any) (result Boolean) {
	_, err := marshalSubstringAssertion(x)
	result.Set(err == nil)
	return
}

func marshalSubstringAssertion(z any) (ssa SubstringAssertion, err error) {
	var x string
	if x, err = assertSubstringAssertion(z); err != nil {
		return
	}

	x = trimS(x)
	f := hasPfx(x, `*`)
	l := hasSfx(x, `*`)
	if cntns(x, `**`) {
		err = errorTxt("SubstringAssertion cannot contain consecutive asterisks")
		return
	} else if !cntns(x, `*`) {
		err = errorTxt("SubstringAssertion requires at least one asterisk")
		return
	}

	if f && l {
		// Any only
		ssa.Any, err = substrProcess1(x)
	} else if f && !l {
		// Final + Any
		ssa.Any, ssa.Final, err = substrProcess2(x)
	} else if !f && l {
		// Initial + Any
		ssa.Initial, ssa.Any, err = substrProcess3(x)
	} else if !f && !l {
		ssa.Initial, ssa.Any, ssa.Final, err = substrProcess4(x)
	}

	return
}

func substrProcess1(x string) (a AssertionValue, err error) {
	z := x[1 : len(x)-1]
	sp := split(z, `*`)
	asp := join(sp, ``)
	if err = assertionValueRunes(asp); err == nil {
		a = AssertionValue(z)
	}

	return
}

func substrProcess2(x string) (a, f AssertionValue, err error) {
	z := x[1:]
	sp := split(z, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	if len(sp) == 1 {
		f = AssertionValue(sp[len(sp)-1])
	} else {
		a = AssertionValue(join(sp[:len(sp)-1], `*`))
		f = AssertionValue(sp[len(sp)-1])
	}

	return
}

func substrProcess3(x string) (i, a AssertionValue, err error) {
	z := x[:len(x)-1]
	sp := split(z, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	if len(sp) == 1 {
		i = AssertionValue(sp[0])
	} else {
		i = AssertionValue(sp[0])
		a = AssertionValue(join(sp[1:], `*`))
	}

	return
}

func substrProcess4(x string) (i, a, f AssertionValue, err error) {
	sp := split(x, `*`)
	for idx := 0; idx < len(sp) && err == nil; idx++ {
		err = assertionValueRunes(sp[idx])
	}

	switch len(sp) {
	case 0, 1:
		err = errorTxt("SubstringAssertion requires at least one asterisk")
	case 2:
		i = AssertionValue(sp[0])
		f = AssertionValue(sp[1])
	default:
		i = AssertionValue(sp[0])
		a = AssertionValue(join(sp[1:len(sp)-1], `*`))
		f = AssertionValue(sp[len(sp)-1])
	}

	return
}

func assertSubstringAssertion(x any) (value string, err error) {
	switch tv := x.(type) {
	case string:
		value = tv
	case []byte:
		value = string(tv)
	case SubstringAssertion:
		value = tv.String()
	default:
		err = errorBadType("SubstringAssertion")
	}

	return
}

/*
caseIgnoreSubstringsMatch implements [§ 4.2.13 of RFC 4517].

OID: 2.5.13.4.

[§ 4.2.13 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.13
*/
func caseIgnoreSubstringsMatch(a, b any) (result Boolean, err error) {
	result, err = substringsMatch(a, b, true)
	return
}

/*
caseIgnoreSubstringsMatch implements [§ 4.2.6 of RFC 4517].

OID: 2.5.13.7.

[§ 4.2.6 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.6
*/
func caseExactSubstringsMatch(a, b any) (result Boolean, err error) {
	result, err = substringsMatch(a, b, false)
	return
}

func substringsMatch(a, b any, caseIgnore ...bool) (result Boolean, err error) {
	var value string
	if value, err = assertString(a, 1, "actual value"); err != nil {
		return
	}

	var B SubstringAssertion
	if B, err = marshalSubstringAssertion(b); err != nil {
		return
	}

	caseHandler := func(val string) string { return val }

	if len(caseIgnore) > 0 {
		if caseIgnore[0] {
			caseHandler = lc
		}
	}

	value = caseHandler(value)

	if B.Any == nil {
		err = errorBadType("Missing SubstringAssertion.Any")
		return
	}

	if B.Initial != nil {
		initialStr := caseHandler(string(B.Initial))

		if !hasPfx(value, initialStr) {
			result.Set(false)
			return
		}
		value = trimPfx(value, initialStr)
	}

	anyStr := `*` + trim(caseHandler(string(B.Any)), `*`) + `*`
	substrings := split(anyStr, "*")
	for _, substr := range substrings {
		index := stridx(value, substr)
		if index == -1 {
			result.Set(false)
			return
		}
		value = value[index+len(substr):]
	}

	if B.Final != nil {
		finalStr := caseHandler(string(B.Final))
		result.Set(hasSfx(value, finalStr))
		return
	}

	result.Set(true)

	return
}

func prepareStringListAssertion(a, b any) (str1, str2 string, err error) {
	assertSubstringsList := func(x any) (list string, err error) {
		var ok bool
		var slices []string
		if slices, ok = x.([]string); ok {
			list = join(slices, ``)
			list = repAll(list, `\\`, ``)
			list = repAll(list, `$`, ``)
		} else {
			errorBadType("substringslist")
		}
		return
	}

	if str1, err = assertSubstringsList(a); err == nil {
		str2, err = assertSubstringsList(b)
	}

	return
}

func caseIgnoreListSubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareStringListAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}
