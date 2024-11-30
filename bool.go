package dirsyn

/*
Boolean wraps a pointer to bool to implement the ASN.1 BOOLEAN type.

From [§ 3.3.3 of RFC 4517]

	Boolean = "TRUE" / "FALSE"

A zero instance of this type is equivalent to "UNDEFINED" (neither TRUE
nor FALSE).

[§ 3.3.3 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
*/
type Boolean struct {
	*bool
}

/*
Boolean returns an instance of [Boolean] alongside an error.

Valid input types are native Go Booleans, string representations of
Booleans and nil.

If the input is a Go Boolean, true is equal to "TRUE" in the context of
directory values, while false is equal to "FALSE". The return error instance
shall always be nil.

If the input is a string, case is not significant in the matching process.
A value of "TRUE" returns a Go Boolean of true, while "FALSE" returns false.
Any other string value results in an error.

If the input is nil, the return is a zero instance of [Boolean].

All other input types return an error.

From [§ 3.3.3 of RFC 4517]:

	Boolean = "TRUE" / "FALSE"

[§ 3.3.3 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
*/
func (r RFC4517) Boolean(x any) (b Boolean, err error) {
	b, err = assertBoolean(x)
	return
}

func boolean(x any) (result Boolean) {
	_, err := assertBoolean(x)
	result.Set(err == nil)
	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r Boolean) IsZero() bool {
	return r.bool == nil
}

/*
Undefined wraps [Boolean.IsZero] and indicates a state that is neither
true nor false.
*/
func (r Boolean) Undefined() bool { return r.IsZero() }

/*
True returns a Boolean value indicative of a true receiver state.
*/
func (r Boolean) True() (v bool) {
	if !r.IsZero() {
		v = (*r.bool) == true
	}

	return
}

/*
False returns a Boolean value indicative of a false receiver state.
*/
func (r Boolean) False() (v bool) {
	if !r.IsZero() {
		v = (*r.bool) != true
	}

	return
}

/*
Set assigns the indicated truthy input value to the receiver instance.

Valid input types are string, *bool, bool or nil.  Case is not significant
in the matching process involving strings.
*/
func (r *Boolean) Set(b any) {
	switch tv := b.(type) {
	case *bool:
		r.bool = tv
	case bool:
		r.bool = &tv
	case nil:
		r.bool = nil
	case string:
		var t bool
		switch uc(tv) {
		case `TRUE`:
			t = true
			r.bool = &t
		case `FALSE`:
			r.bool = &t
		}
	}
}

func (r Boolean) String() (s string) {
	s = "UNDEFINED"
	if !r.IsZero() {
		s = "FALSE"
		if *r.bool {
			s = "TRUE"
		}
	}

	return
}

func assertBoolean(x any) (b Boolean, err error) {
	switch tv := x.(type) {
	case nil:
	case Boolean:
		b = tv
	case bool:
		b = Boolean{&tv}
	case string:
		if !(streqf(tv, `TRUE`) || streqf(tv, `FALSE`)) {
			err = errorTxt("Invalid Boolean " + tv)
		} else {
			_b := uc(tv) == `TRUE`
			b = Boolean{&_b}
		}
	default:
		err = errorBadType("Boolean")
	}

	return
}

/*
booleanMatch implements [§ 4.2.2 of RFC 4517].

OID: 2.5.13.13.

[§ 4.2.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.2
*/
func booleanMatch(a, b any) (result Boolean, err error) {

	var A, B Boolean
	if A, err = assertBoolean(a); err != nil {
		return
	}
	if B, err = assertBoolean(b); err != nil {
		return
	}

	if A.True() {
		result.Set(B.True())
	} else if A.False() {
		result.Set(B.False())
	} else if A.Undefined() {
		result.Set(B.Undefined())
	}

	return
}
