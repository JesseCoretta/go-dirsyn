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
	return processSubstringAssertion(x)
}

func processSubstringAssertion(z any) (ssa SubstringAssertion, err error) {
	var x string
	switch tv := z.(type) {
	case string:
		x = tv
	case []byte:
		x = string(tv)
	default:
		err = errorBadType("Substring Assertion")
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
	for idx := 0; idx < len(sp); idx++ {
		if err = assertionValueRunes(sp[idx]); err != nil {
			return
		}
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
	for idx := 0; idx < len(sp); idx++ {
		if err = assertionValueRunes(sp[idx]); err != nil {
			return
		}
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
	for idx := 0; idx < len(sp); idx++ {
		if err = assertionValueRunes(sp[idx]); err != nil {
			return
		}
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
