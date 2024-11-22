package dirsyn

/*
filter.go contains RFC4515 methods and types.
*/

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
Filter returns a [Filter] qualifier instance alongside an error.

If the input is nil, the default [PresentFilter] (e.g.: "(objectClass=*)")
is returned.

If the input is a string, an attempt to marshal the value is made. If
the string is zero, this is equivalent to providing nil.

If the input is a *[ber.Packet] instance, it is unmarshaled into the
return instance of [Filter].

Any errors found will result in the return of an invalid [Filter] instance.
*/
func (r RFC4515) Filter(x any) (filter Filter, err error) {
	switch tv := x.(type) {
	case nil:
		// Nil returns the default filter.
		filter, err = r.Filter(``)
		return
	case string:
		// try to handle a zero length string
		// filter (default return).
		if len(tv) == 0 {
			filter = PresentFilter{
				Desc: AttributeDescription(`objectClass`),
			}
			return
		}
	case *ber.Packet:
		// unmarshal BER encoding into Filter instance
		filter, err = unmarshalFilterBER(tv)
		return
	}

	if filter, err = processFilter(x); filter == nil {
		// just to avoid panics in the event
		// the user does not check errors.
		filter = invalidFilter{}
		err = errorTxt("Invalid filter")
	}

	return
}

/*
Filter implements [Section 2] and [Section 3] of RFC4515.

[Section 2]: https://datatracker.ietf.org/doc/html/rfc4515#section-2
[Section 3]: https://datatracker.ietf.org/doc/html/rfc4515#section-3
*/
type Filter interface {
	// BER returns the BER encoding of the receiver
	// instance alongside an error. The *ber.Packet
	// instance can be decoded back to an instance
	// of Filter via the RFC4515.Filter method.
	BER() (*ber.Packet, error)

	// Index returns the Nth slice index found within
	// the receiver instance. This is only useful if
	// the receiver is an AndFilter or OrFilter Filter
	// qualifier type instance.
	Index(int) Filter

	// IsZero returns a Boolean value indicative of
	// a nil receiver state.
	IsZero() bool

	// String returns the string representation of
	// the receiver instance.
	String() string

	// Choice returns the string CHOICE "name" of the
	// receiver instance. Use of this method is merely
	// intended as a convenient alternative to type
	// assertion checks.
	Choice() string

	// Len returns the integer length of the receiver
	// instance. This is only useful if the receiver is
	// an AndFilter or OrFilter Filter qualifier type
	// instance.
	Len() int
}

type invalidFilter struct{}

/*
AndFilter implements the "and" CHOICE of an instance of [Filter].
*/
type AndFilter []Filter

/*
OrFilter implements the "or" CHOICE of an instance of [Filter].
*/
type OrFilter []Filter

/*
NotFilter implements the "not" CHOICE of an instance of [Filter].
*/
type NotFilter struct {
	Filter
}

/*
EqualityMatchFilter aliases the [AttributeValueAssertion] type to implement
the "equalityMatch" CHOICE of an instance of [Filter].
*/
type EqualityMatchFilter AttributeValueAssertion

/*
GreaterOrEqualFilter aliases the [AttributeValueAssertion] type to implement
the "greaterOrEqual" CHOICE of an instance of [Filter].
*/
type GreaterOrEqualFilter AttributeValueAssertion

/*
LessOrEqualFilter aliases the [AttributeValueAssertion] type to implement
the "lessOrEqual" CHOICE of an instance of [Filter].
*/
type LessOrEqualFilter AttributeValueAssertion

/*
ApproximateMatchFilter aliases the [AttributeValueAssertion] type to implement
the "approxMatch" CHOICE of an instance of [Filter].
*/
type ApproximateMatchFilter AttributeValueAssertion

/*
AttributeValueAssertion implements the basis for [ApproximateMatchFilter],
[GreaterOrEqualFilter], [LessOrEqualFilter] and [EqualityMatchFilter].

	AttributeValueAssertion ::= SEQUENCE {
	    attributeDesc   AttributeDescription,
	    assertionValue  AssertionValue }
*/
type AttributeValueAssertion struct {
	Desc  AttributeDescription
	Value AssertionValue
}

/*
AttributeDescription implements the LDAPString description component of
an instance of [AttributeValueAssertion].
*/
type AttributeDescription string

/*
AssertionValue implements the OCTET STRING value component of an instance
of [AttributeValueAssertion].
*/
type AssertionValue []uint8

/*
PresentFilter implements the "present" CHOICE of an instance of [Filter].
*/
type PresentFilter struct {
	Desc AttributeDescription
}

/*
ExtensibleMatchFilter aliases the [MatchingRuleAssertionFilter] to implement
the "extensibleMatch" CHOICE of an instance of [Filter].
*/
type ExtensibleMatchFilter MatchingRuleAssertionFilter

/*
MatchingRuleAssertion implements the basis of [ExtensibleMatchFilter].

	MatchingRuleAssertion ::= SEQUENCE {
	    matchingRule    [1] MatchingRuleId OPTIONAL,
	    type            [2] AttributeDescription OPTIONAL,
	    matchValue      [3] AssertionValue,
	    dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/
type MatchingRuleAssertionFilter struct {
	MatchingRule string               `asn1:"tag:1,optional"`
	Type         AttributeDescription `asn1:"tag:2,optional"`
	MatchValue   AssertionValue       `asn1:"tag:3"`
	DNAttributes bool                 `asn1:"tag:4,default:false"`
}

/*
SubstringsFilter implements the "substrings" CHOICE of an instance of [Filter].
*/
type SubstringsFilter struct {
	Type       AttributeDescription
	Substrings SubstringAssertion
}

func (r invalidFilter) IsZero() bool { return true }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AndFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r OrFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NotFilter) IsZero() bool { return r.Filter == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r EqualityMatchFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r GreaterOrEqualFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LessOrEqualFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ApproximateMatchFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PresentFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r SubstringsFilter) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ExtensibleMatchFilter) IsZero() bool { return &r == nil }

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r AndFilter) Index(idx int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			filter = r[idx]
		}
	}

	return
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r OrFilter) Index(idx int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			filter = r[idx]
		}
	}

	return
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r NotFilter) Index(idx int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r.Filter.Index(idx)
	}

	return
}

/*
Index returns an invalid [Filter] instance. This method only exists to
satisfy Go's interface signature requirement.
*/
func (r invalidFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}
	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r GreaterOrEqualFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r LessOrEqualFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r EqualityMatchFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r SubstringsFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r ApproximateMatchFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r PresentFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
Index returns the receiver instance of [Filter]. This method only exists
to satisfy Go's interface signature requirement.
*/
func (r ExtensibleMatchFilter) Index(_ int) (filter Filter) {
	filter = invalidFilter{}

	if !r.IsZero() {
		filter = r
	}

	return
}

/*
String returns a zero string.
*/
func (r invalidFilter) String() string { return `` }

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeDescription) String() string {
	return string(r)
}

/*
String returns the string representation of the receiver instance.
Note that this method is an alias of [AssertionValue.Escaped].
*/
func (r AssertionValue) String() string {
	return r.Escaped()
}

func (r AssertionValue) Unescaped() string {
	var u string
	if len(r) > 0 {
		u = hexDecode(string(r))
	}

	return u
}

func (r AssertionValue) Escaped() (esc string) {
	if len(r) > 0 {
		esc = escapeString(string(r))
	}

	return
}

/*
Set assigns x to the receiver instance.
*/
func (r *AssertionValue) Set(x any) {
	var s string
	switch tv := x.(type) {
	case string:
		s = tv
	case []byte:
		s = string(tv)
	default:
		return
	}

	*r = AssertionValue(escapeString(s))
}

/*
String returns the string representation of the receiver instance.
*/
func (r AndFilter) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "(&" + join(parts, "") + ")"
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r OrFilter) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "(|" + join(parts, "") + ")"
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r NotFilter) String() (s string) {
	if !r.IsZero() {
		s = "(!" + r.Filter.String() + ")"
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r EqualityMatchFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r GreaterOrEqualFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `>=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r LessOrEqualFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `<=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ApproximateMatchFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `~=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r PresentFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `=*` + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubstringsFilter) String() (s string) {
	if !r.IsZero() {
		s = `(` + string(r.Type) + `=` + r.Substrings.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ExtensibleMatchFilter) String() (s string) {
	if !r.IsZero() {
		if r.MatchValue == nil {
			return
		}

		value := r.MatchValue.String()
		typ := r.Type.String()
		mr := r.MatchingRule
		dna := r.DNAttributes

		if typ != "" && mr == "" {
			if dna {
				s = typ + `:dn:=` + value
			} else {
				s = typ + `:=` + value
			}
		} else if typ == "" && mr != "" {
			if dna {
				s = `:dn:` + mr + `:=` + value
			} else {
				s = `:` + mr + `:=` + value
			}
		} else if typ != "" && mr != "" {
			if dna {
				s = typ + `:dn:` + mr + `:=` + value
			} else {
				s = typ + `:` + mr + `:=` + value
			}
		}

		if s != "" {
			s = `(` + s + `)`
		}
	}

	return
}

func (r invalidFilter) Choice() string { return "invalid" }

/*
Choice returns the string literal CHOICE "and".
*/
func (r AndFilter) Choice() string { return "and" }

/*
Choice returns the string literal CHOICE "or".
*/
func (r OrFilter) Choice() string { return "or" }

/*
Choice returns the string literal CHOICE "not".
*/
func (r NotFilter) Choice() string { return "not" }

/*
Choice returns the string literal CHOICE "equalityMatch".
*/
func (r EqualityMatchFilter) Choice() string { return "equalityMatch" }

/*
Choice returns the string literal CHOICE "greaterOrEqual".
*/
func (r GreaterOrEqualFilter) Choice() string { return "greaterOrEqual" }

/*
Choice returns the string literal CHOICE "lessOrEqual".
*/
func (r LessOrEqualFilter) Choice() string { return "lessOrEqual" }

/*
Choice returns the string literal CHOICE "approxMatch".
*/
func (r ApproximateMatchFilter) Choice() string { return "approxMatch" }

/*
Choice returns the string literal CHOICE "present".
*/
func (r PresentFilter) Choice() string { return "present" }

/*
Choice returns the string literal CHOICE "substrings".
*/
func (r SubstringsFilter) Choice() string { return "substrings" }

/*
Choice returns the string literal CHOICE "extensibleMatch".
*/
func (r ExtensibleMatchFilter) Choice() string { return "extensibleMatch" }

func (r invalidFilter) tag() uint64          { return 0 }
func (r AndFilter) tag() uint64              { return 1 }
func (r OrFilter) tag() uint64               { return 2 }
func (r NotFilter) tag() uint64              { return 3 }
func (r EqualityMatchFilter) tag() uint64    { return 4 }
func (r SubstringsFilter) tag() uint64       { return 5 }
func (r GreaterOrEqualFilter) tag() uint64   { return 6 }
func (r LessOrEqualFilter) tag() uint64      { return 7 }
func (r PresentFilter) tag() uint64          { return 8 }
func (r ApproximateMatchFilter) tag() uint64 { return 9 }
func (r ExtensibleMatchFilter) tag() uint64  { return 10 }

func (r invalidFilter) Len() int { return 0 }

/*
Len returns the integer length of the receiver instance.
*/
func (r AndFilter) Len() int { return len(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r OrFilter) Len() int { return len(r) }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r NotFilter) Len() int {
	if !r.IsZero() {
		return r.Filter.Len()
	}

	return 0
}

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r EqualityMatchFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r GreaterOrEqualFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r LessOrEqualFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r ApproximateMatchFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r PresentFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r SubstringsFilter) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r ExtensibleMatchFilter) Len() int { return 1 }

func processFilter(x any) (filter Filter, err error) {
	var input string
	if input, err = assertString(x, 1, "Search Filter"); err != nil {
		return
	}

	if input = trimS(input); input == "" {
		filter = PresentFilter{Desc: AttributeDescription("objectClass")}
		return
	} else if cntns(input, `((`) || !checkParenBalanced(input) {
		err = errorTxt(`unexpected end of filter`)
		filter = invalidFilter{}
		return
	}

	switch {
	case hasPfx(input, "(&"):
		filter, err = parseAndFilter(input)
	case hasPfx(input, "(|"):
		filter, err = parseOrFilter(input)
	case hasPfx(input, "(!"):
		filter, err = parseNotFilter(input)
	default:
		filter, err = parseItemFilter(input)
	}

	return
}

func parseAndFilter(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "&")
}

func parseOrFilter(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "|")
}

func parseNotFilter(input string) (Filter, error) {
	if len(input) < 8 {
		return invalidFilter{}, errorTxt("Invalid NotFilter")
	}
	subRef, err := processFilter(input[2 : len(input)-1])
	if err != nil {
		return nil, err
	}
	return NotFilter{subRef}, nil
}

func parseComplexFilter(input, prefix string) (Filter, error) {
	var refs []Filter
	parts := splitFilterParts(input)
	for _, part := range parts {
		subRef, err := processFilter(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, subRef)
	}
	if prefix == "&" {
		return AndFilter(refs), nil
	}
	return OrFilter(refs), nil
}

func parseItemFilter(input string) (filter Filter, err error) {
	idx := stridx(input, "=")
	if idx == -1 {
		err = errorTxt("Nil filter item")
		filter = invalidFilter{}
		return
	}

	var cerr error // assertionValue character set errors

	pre, after := input[:idx], input[idx+1:]

	// Verify parenthetical encapsulation is balanced
	if err = checkParenEncaps(pre, after); err != nil {
		filter = invalidFilter{}
		return
	}

	// Now that we've verified them, parenthetical
	// encapsulators will just get in the way, so
	// let's strip them off. They will reappear
	// during string representation.
	pre = repAll(pre, `(`, ``)
	after = repAll(after, `)`, ``)

	if after == `*` {
		err = checkFilterOIDs(pre, ``)
		filter = PresentFilter{
			Desc: AttributeDescription(pre)}
	} else if hasSfx(pre, `>`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = GreaterOrEqualFilter{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if hasSfx(pre, `<`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = LessOrEqualFilter{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if hasSfx(pre, `~`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = ApproximateMatchFilter{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if cntns(after, "*") {
		var ssa SubstringAssertion
		if ssa, err = processSubstringAssertion(after); err == nil {
			err = checkFilterOIDs(pre, ``)
			filter = SubstringsFilter{
				Type:       AttributeDescription(pre),
				Substrings: ssa}
		}
	} else if cntns(pre, ":") {
		filter, err = parseExtensibleMatch(pre, after)
		cerr = assertionValueRunes(after, true)
	} else {
		err = checkFilterOIDs(pre, ``)
		cerr = assertionValueRunes(after, true)
		filter = EqualityMatchFilter{
			Desc:  AttributeDescription(pre),
			Value: AssertionValue(after)}
	}

	if err != nil || cerr != nil {
		filter = invalidFilter{}
	}

	return
}

func parseExtensibleMatch(a, b string) (filter Filter, err error) {
	scol := hasPfx(a, `:`)
	sdn := hasPfx(a, `:dn:`) || hasPfx(a, `:DN:`)

	val := AssertionValue(b)
	_filter := ExtensibleMatchFilter{}

	if !scol {
		if !valueIsDNAttrs(a) {
			if idx := idxr(a, ':'); idx != -1 {
				mr := trim(a[idx+1:], `:`)
				err = checkFilterOIDs(a[:idx], mr)
				_filter.Type = AttributeDescription(a[:idx])
				_filter.MatchingRule = mr
			}
		} else {
			_filter.DNAttributes = true
			if c := dnAttrSplit(a); len(c) == 2 {
				mr := trim(c[1], `:`)
				err = checkFilterOIDs(c[0], mr)
				if len(c[0]) > 0 && len(c[1]) > 0 {
					_filter.Type = AttributeDescription(c[0])
					_filter.MatchingRule = mr
				} else if len(c[0]) > 0 {
					_filter.Type = AttributeDescription(c[0])
				} else if len(c[1]) > 0 {
					_filter.MatchingRule = c[1]
				}
			}
		}
		_filter.MatchValue = val
	} else if scol {
		if sdn {
			_filter.DNAttributes = true
			_filter.MatchingRule = a[4 : len(a)-1]
		} else {
			_filter.MatchingRule = a[1 : len(a)-1]
		}
		err = checkFilterOIDs(``, _filter.MatchingRule)
		_filter.MatchValue = val
	}

	if err == nil && !_filter.IsZero() {
		filter = _filter
	}

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r AndFilter) BER() (*ber.Packet, error) {
	if r.IsZero() || r.Len() == 0 {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		child, err := r[i].BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	return packet, nil

}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r OrFilter) BER() (*ber.Packet, error) {
	if r.IsZero() || r.Len() == 0 {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		child, err := r[i].BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r NotFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	not, err := r.Filter.BER()
	if err != nil {
		return nil, err
	}

	packet.AppendChild(not)

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r EqualityMatchFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Desc,
		`attributeDescription`))
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Value,
		`assertionValue`))

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r ApproximateMatchFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Desc,
		`attributeDescription`))
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Value,
		`assertionValue`))

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r GreaterOrEqualFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Desc,
		`attributeDescription`))
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Value,
		`assertionValue`))

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r LessOrEqualFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Desc,
		`attributeDescription`))
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Value,
		`assertionValue`))

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r PresentFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	}

	return ber.Encode(ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(r.tag()),
		r.Desc,
		r.Choice()), nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r SubstringsFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Filter, cannot BER encode")
	} else if r.Substrings.IsZero() {
		return nil, errorTxt("Nil Substring Assertion, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())
	packet.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.TagOctetString,
		r.Type,
		`attributeDescription`))
	substr := ber.Encode(ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
		r.Choice())

	if len(r.Substrings.Initial) > 0 {
		substr.AppendChild(ber.Encode(ber.ClassContext,
			ber.TypeConstructed,
			ber.Tag(0),
			r.Substrings.Initial,
			`initial`))
	}

	substr.AppendChild(ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(1),
		r.Substrings.Any,
		`any`))

	if len(r.Substrings.Final) > 0 {
		substr.AppendChild(ber.Encode(ber.ClassContext,
			ber.TypeConstructed,
			ber.Tag(2),
			r.Substrings.Final,
			`final`))
	}

	packet.AppendChild(substr)
	return packet, nil
}

func unmarshalPresentFilterBER(packet *ber.Packet) (item Filter, err error) {

	if str, ok := packet.Value.(AttributeDescription); !ok {
		item = invalidFilter{}
		err = errorTxt("Invalid or absent AttributeDescription; cannot unmarshal")
	} else {
		item = PresentFilter{Desc: AttributeDescription(str)}
	}

	return
}

func unmarshalGeLeFilterBER(packet *ber.Packet) (item Filter, err error) {
	if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Ge/Le sequence fields (want:2); cannot unmarshal")
		item = invalidFilter{}
		return
	}

	typ := packet.Description
	atd := packet.Children[0]
	val := packet.Children[1]

	a, aok := atd.Value.(AttributeDescription)
	v, vok := val.Value.(AssertionValue)

	if !aok || !vok {
		err = errorTxt("Invalid or absent Ge/Le descr or value; cannot unmarshal")
		item = invalidFilter{}
	} else {
		if typ == "greaterOrEqual" {
			item = GreaterOrEqualFilter{Desc: AttributeDescription(a), Value: AssertionValue(v)}
		} else if typ == "lessOrEqual" {
			item = LessOrEqualFilter{Desc: AttributeDescription(a), Value: AssertionValue(v)}
		} else {
			err = errorTxt("Invalid or absent type identifier; cannot unmarshal")
			item = invalidFilter{}
		}
	}

	return
}

func unmarshalApproxFilterBER(packet *ber.Packet) (item Filter, err error) {
	if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Approx sequence fields (want:2); cannot unmarshal")
		item = invalidFilter{}
		return
	}

	atd := packet.Children[0]
	val := packet.Children[1]

	a, aok := atd.Value.(AttributeDescription)
	v, vok := val.Value.(AssertionValue)

	if !aok || !vok {
		err = errorTxt("Invalid or absent Approx descr or value; cannot unmarshal")
		item = invalidFilter{}
	} else {
		item = ApproximateMatchFilter{Desc: AttributeDescription(a), Value: AssertionValue(v)}
	}

	return
}

func unmarshalExtensibleFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	lc := len(packet.Children)
	if !(1 <= lc && lc < 5) {
		err = errorTxt("Unexpected number of Extensible seq fields (want:1-4); cannot unmarshal")
		return
	}

	_item := ExtensibleMatchFilter{}

	var val bool
	for i := 0; i < lc && _item.Choice() != "invalid"; i++ {
		child := packet.Children[i]
		var ok bool
		switch uint64(child.Tag) {
		case 1:
			if _item.MatchingRule, ok = child.Value.(string); !ok {
				err = errorTxt("Invalid MatchingRule for extensible filter (want:string)")
			}
		case 2:
			if _item.Type, ok = child.Value.(AttributeDescription); !ok {
				err = errorTxt("Invalid Attribute for extensible filter (want:AttributeDescription)")
			}
		case 3:
			if _item.MatchValue, val = child.Value.(AssertionValue); !val {
				err = errorTxt("Invalid MatchingValue for extensible filter (want:AssertionValue)")
			}
		case 4:
			if _item.DNAttributes, ok = child.Value.(bool); !ok {
				err = errorTxt("Invalid DNAttributes for extensible filter (want:bool)")
			}
		}
	}

	if err == nil {
		item = _item
	}

	return
}

func unmarshalEqualityFilterBER(packet *ber.Packet) (item Filter, err error) {
	if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Approx seq fields (want:2); cannot unmarshal")
		item = invalidFilter{}
		return
	}

	atd := packet.Children[0]
	val := packet.Children[1]

	a, aok := atd.Value.(AttributeDescription)
	v, vok := val.Value.(AssertionValue)

	if !aok || !vok {
		err = errorTxt("Invalid or absent Equality descr or value; cannot unmarshal")
		item = invalidFilter{}
	} else {
		item = EqualityMatchFilter{Desc: AttributeDescription(a), Value: AssertionValue(v)}
	}

	return
}

func unmarshalSubstringsFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of AttributeType instances (want:2); cannot unmarshal")
		return
	}

	at := packet.Children[0]
	ss := packet.Children[1]

	lc := len(ss.Children)
	if !(1 <= lc && lc < 4) {
		err = errorTxt("Unexpected number of AssertionValue instances (want 1-3); cannot unmarshal")
		return
	}

	_item := SubstringsFilter{
		Type:       at.Value.(AttributeDescription),
		Substrings: SubstringAssertion{},
	}

	var Any bool
	for i := 0; i < lc; i++ {
		child := ss.Children[i]
		switch uint64(child.Tag) {
		case 0:
			_item.Substrings.Initial = AssertionValue(child.Value.(AssertionValue))
		case 1:
			_item.Substrings.Any = AssertionValue(child.Value.(AssertionValue))
			Any = true
		case 2:
			_item.Substrings.Final = AssertionValue(child.Value.(AssertionValue))
		}
	}

	if !Any {
		err = errorTxt("Missing Substrings.Any assertion value; cannot unmarshal")
		item = invalidFilter{}
	} else {
		item = _item
	}

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r ExtensibleMatchFilter) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil filter, cannot BER encode")
	}

	packet := ber.NewSequence(r.Choice())

	if len(r.MatchValue) > 0 {
		packet.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			ber.Tag(1),
			r.MatchingRule,
			`matchingRule`))
	}

	if len(r.Type) > 0 {
		packet.AppendChild(ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			ber.Tag(2),
			r.Type,
			`attributeDescription`))
	}

	packet.AppendChild(ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(3),
		r.MatchValue,
		`assertionValue`))

	if r.DNAttributes {
		packet.AppendChild(ber.NewBoolean(
			ber.ClassContext,
			ber.TypePrimitive,
			ber.Tag(4),
			r.DNAttributes,
			`dNAttributes`))
	}

	return packet, nil
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r invalidFilter) BER() (*ber.Packet, error) {
	return nil, errorTxt("Nil Filter, cannot BER encode")
}

// Verify parenthetical encapsulation is balanced
func checkParenEncaps(a, b string) (err error) {
	lencap := hasPfx(a, `(`)
	rencap := hasSfx(b, `)`)
	if lencap && !rencap {
		err = errorTxt(`unexpected end of filter`)
	} else if !lencap && rencap {
		err = errorTxt(`unexpected end of filter`)
	}

	return
}

func checkParenBalanced(x string) bool {
	return strcnt(x, `(`) == strcnt(x, `)`)
}

func checkFilterOIDs(t, m string) (err error) {
	r := RFC4512{}
	if len(t) > 0 {
		if err = r.OID(t); err != nil {
			return
		}
	}
	if len(m) > 0 {
		if err = r.OID(m); err != nil {
			return
		}
	}

	return
}

func splitFilterParts(input string) []string {
	var parts []string
	currentPart := newStrBuilder()
	depth := 0
	for _, char := range input {
		switch char {
		case '(':
			if depth == 0 && currentPart.Len() > 0 {
				parts = append(parts, currentPart.String())
				currentPart.Reset()
			}
			depth++
		case ')':
			depth--
		}
		currentPart.WriteRune(char)
	}
	if currentPart.Len() > 0 {
		parts = append(parts, currentPart.String())
	}
	return parts
}

func unmarshalFilterBER(packet *ber.Packet) (filter Filter, err error) {
	filter = invalidFilter{}
	if packet == nil {
		err = errorTxt("Nil Filter BER packet; cannot unmarshal")
		return
	}

	switch packet.Description {
	case "present",
		"substrings",
		"approxMatch",
		"lessOrEqual",
		"equalityMatch",
		"greaterOrEqual",
		"extensibleMatch":
		filter, err = unmarshalItemFilterBER(packet)
	case "not":
		filter, err = unmarshalNotFilterBER(packet)
	case "and", "or":
		filter, err = unmarshalSetFilterBER(packet)
	default:
		err = errorTxt("Unidentified BER packet; cannot unmarshal to Filter")

	}

	return
}

func unmarshalItemFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}

	switch packet.Description {
	case "equalityMatch":
		item, err = unmarshalEqualityFilterBER(packet)
	case "present":
		item, err = unmarshalPresentFilterBER(packet)
	case "substrings":
		item, err = unmarshalSubstringsFilterBER(packet)
	case "approxMatch":
		item, err = unmarshalApproxFilterBER(packet)
	case "lessOrEqual", "greaterOrEqual":
		item, err = unmarshalGeLeFilterBER(packet)
	case "extensibleMatch":
		item, err = unmarshalExtensibleFilterBER(packet)
	default:
		err = errorTxt("Invalid BER packet; cannot unmarshal")
	}

	return
}

func unmarshalSetFilterBER(packet *ber.Packet) (filter Filter, err error) {
	lc := len(packet.Children)
	filter = invalidFilter{}

	var filters []Filter
	and := packet.Description == "and"

	if lc == 0 || packet.Description == "invalid" || !(and || packet.Description == "or") {
		err = errorTxt("No Filter qualifiers present within set packet; cannot unmarshal")
		return
	}

	for i := 0; i < lc && err == nil; i++ {
		child := packet.Children[i]
		var subfilter Filter
		if subfilter, err = unmarshalFilterBER(child); err == nil {
			filters = append(filters, subfilter)
		}
	}

	if err != nil {
		filter = invalidFilter{}
	} else if and {
		filter = AndFilter(filters)
	} else {
		filter = OrFilter(filters)
	}

	return
}

func unmarshalNotFilterBER(packet *ber.Packet) (filter Filter, err error) {
	filter = invalidFilter{}
	if len(packet.Children) != 1 {
		err = errorTxt("Invalid Not Filter (no payload); cannot unmarshal")
		return
	}

	var nest Filter
	if nest, err = unmarshalFilterBER(packet.Children[0]); err == nil {
		filter = NotFilter{nest}
	}

	return
}
