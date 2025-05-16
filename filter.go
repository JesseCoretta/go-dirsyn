package dirsyn

/*
filter.go contains RFC4515 methods and types.
*/

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
Filter returns a [Filter] qualifier instance alongside an error.

If the input is nil, the default [FilterPresent] (e.g.: "(objectClass=*)")
is returned.

If the input is a string, an attempt to marshal the value is made. If
the string is zero, this is equivalent to providing nil.

If the input is a *[ber.Packet] instance describing a previously parsed
[Filter], it is unmarshaled into the return instance of [Filter].

Any errors found will result in the return of an invalid [Filter] instance.
*/
func (r RFC4515) Filter(x any) (Filter, error) {
	return marshalFilter(x)
}

func marshalFilter(x any) (filter Filter, err error) {
	switch tv := x.(type) {
	case nil:
		// Nil returns the default filter.
		filter, err = marshalFilter(``)
		return
	case string:
		// try to handle a zero length string
		// filter (default return).
		if len(tv) == 0 {
			filter = FilterPresent{
				Desc: AttributeDescription(`objectClass`),
			}
			return
		}
	case *ber.Packet:
		// unmarshal BER encoding into Filter instance
		filter, err = unmarshalFilterBER(tv)
		return
	}

	if filter, err = parseSubFilter(x); filter == nil {
		// just to avoid panics in the event
		// the user does not check errors.
		filter = invalidFilter{}
		err = invalidFilterErr
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
	// the receiver is an FilterAnd or FilterOr Filter
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
	// an FilterAnd or FilterOr Filter qualifier type
	// instance.
	Len() int

	// Size returns the integer summation of the tag value
	// and the underlying byte value size(s).
	Size() int

	// Differentiate Filter qualifiers from other
	// unrelated interfaces.
	isFilter()
}

type invalidFilter struct{}

/*
FilterAnd implements the "and" CHOICE of an instance of [Filter].
*/
type FilterAnd []Filter

/*
FilterOr implements the "or" CHOICE of an instance of [Filter].
*/
type FilterOr []Filter

/*
FilterNot implements the "not" CHOICE of an instance of [Filter].
*/
type FilterNot struct {
	Filter
}

/*
FilterEqualityMatch aliases the [AttributeValueAssertion] type to implement
the "equalityMatch" CHOICE of an instance of [Filter].
*/
type FilterEqualityMatch AttributeValueAssertion

/*
FilterGreaterOrEqual aliases the [AttributeValueAssertion] type to implement
the "greaterOrEqual" CHOICE of an instance of [Filter].
*/
type FilterGreaterOrEqual AttributeValueAssertion

/*
FilterLessOrEqual aliases the [AttributeValueAssertion] type to implement
the "lessOrEqual" CHOICE of an instance of [Filter].
*/
type FilterLessOrEqual AttributeValueAssertion

/*
FilterApproximateMatch aliases the [AttributeValueAssertion] type to implement
the "approxMatch" CHOICE of an instance of [Filter].
*/
type FilterApproximateMatch AttributeValueAssertion

/*
AttributeValueAssertion implements the basis for [FilterApproximateMatch],
[FilterGreaterOrEqual], [FilterLessOrEqual] and [FilterEqualityMatch]
instances.

	AttributeValueAssertion ::= SEQUENCE {
	    attributeDesc   AttributeDescription,
	    assertionValue  AssertionValue }
*/
type AttributeValueAssertion struct {
	Desc  AttributeDescription
	Value AssertionValue
}

/*
AttributeDescription implements [Section 2.5 of RFC4512].

[Section 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeDescription LDAPString

/*
AttributeOption implements [Section 2.5 of RFC4512].

[Section 2.5 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5
*/
type AttributeOption interface {
	Kind() string
	String() string
	isAttributeOption()
}

/*
AttributeTag implements [Section 2.5.2 of RFC4512].

[Section 2.5.2 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.5.2
*/
type AttributeTag string

/*
AssertionValue implements the OCTET STRING value component of an instance
of [AttributeValueAssertion].
*/
type AssertionValue []uint8

/*
FilterPresent implements the "present" CHOICE of an instance of [Filter].
*/
type FilterPresent struct {
	Desc AttributeDescription
}

type MatchingRuleID LDAPString

/*
FilterExtensibleMatch aliases the [MatchingRuleAssertion] to implement
the "extensibleMatch" CHOICE of an instance of [Filter].
*/
type FilterExtensibleMatch MatchingRuleAssertion

/*
MatchingRuleAssertion implements the basis of [FilterExtensibleMatch].

	MatchingRuleAssertion ::= SEQUENCE {
	    matchingRule    [1] MatchingRuleId OPTIONAL,
	    type            [2] AttributeDescription OPTIONAL,
	    matchValue      [3] AssertionValue,
	    dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/
type MatchingRuleAssertion struct {
	MatchingRule MatchingRuleID       `asn1:"tag:1,optional"`
	Type         AttributeDescription `asn1:"tag:2,optional"`
	MatchValue   AssertionValue       `asn1:"tag:3"`
	DNAttributes bool                 `asn1:"tag:4,default:false"`
}

/*
FilterSubstrings implements the "substrings" CHOICE of an instance of [Filter].
*/
type FilterSubstrings struct {
	Type       AttributeDescription
	Substrings SubstringAssertion
}

/*
Size returns the integer summation of the underlying value sizes and the ASN.1 SEQUENCE tag (16).
*/
func (r AttributeValueAssertion) Size() int {
	var size int
	size += r.Desc.Size()
	size += r.Value.Size()
	size += sizeTagAndLength(tagSequence, size)
	return size
}

func (r AttributeValueAssertion) sizeTagged(tag uint64) int {
	var size int
	size += r.Desc.Size()
	size += r.Value.Size()
	size += int(tag)
	return size
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleID) String() string { return string(r) }

/*
Size returns the integer summation of the MatchingRuleAssertionMatchingRule tag (1) and
the byte size of the receiver instance
*/
func (r MatchingRuleID) Size() int { return len(r) + tagMatchingRuleAssertionMatchingRule }

func (r MatchingRuleID) sizeTagged(tag uint64) int { return len(r) + int(tag) }

/*
Kind returns the string literal "tag" to describe the kind of [AttributeOption]
represented by the receiver instance.
*/
func (r AttributeTag) Kind() string { return `tag` }

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTag) String() string { return string(r) }

// differentiate Filter qualifiers from other interfaces.
func (r AttributeTag) isAttributeOption()  {}
func (r invalidFilter) isFilter()          {}
func (r FilterAnd) isFilter()              {}
func (r FilterNot) isFilter()              {}
func (r FilterOr) isFilter()               {}
func (r FilterEqualityMatch) isFilter()    {}
func (r FilterPresent) isFilter()          {}
func (r FilterSubstrings) isFilter()       {}
func (r FilterExtensibleMatch) isFilter()  {}
func (r FilterApproximateMatch) isFilter() {}
func (r FilterGreaterOrEqual) isFilter()   {}
func (r FilterLessOrEqual) isFilter()      {}

func (r invalidFilter) IsZero() bool { return true }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterAnd) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterOr) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterNot) IsZero() bool { return r.Filter == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterEqualityMatch) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterGreaterOrEqual) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterLessOrEqual) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterApproximateMatch) IsZero() bool {
	return r.Desc.String() == "" &&
		r.Value == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterPresent) IsZero() bool { return r.Desc.String() == "" }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterSubstrings) IsZero() bool {
	return r.Type.String() == "" &&
		r.Substrings.IsZero()
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r FilterExtensibleMatch) IsZero() bool {
	return r.MatchingRule.String() == "" &&
		r.Type.String() == "" &&
		r.MatchValue == nil &&
		!r.DNAttributes
}

/*
Index returns the Nth [Filter] slice instance from within the receiver.
*/
func (r FilterAnd) Index(idx int) (filter Filter) {
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
func (r FilterOr) Index(idx int) (filter Filter) {
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
func (r FilterNot) Index(idx int) (filter Filter) {
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
func (r FilterGreaterOrEqual) Index(_ int) (filter Filter) {
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
func (r FilterLessOrEqual) Index(_ int) (filter Filter) {
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
func (r FilterEqualityMatch) Index(_ int) (filter Filter) {
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
func (r FilterSubstrings) Index(_ int) (filter Filter) {
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
func (r FilterApproximateMatch) Index(_ int) (filter Filter) {
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
func (r FilterPresent) Index(_ int) (filter Filter) {
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
func (r FilterExtensibleMatch) Index(_ int) (filter Filter) {
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
Type returns only the "descr" component of the receiver instance.

Specifically, this will ensure that elements such as [AttributeOption]
instances -- such as language tags -- are not included in the return
string value.
*/
func (r AttributeDescription) Type() (oid string) {
	oid = r.String()
	if idx := stridx(oid, `;`); idx != -1 {
		oid = oid[:idx]
	}

	return
}

/*
Options returns slices of [AttributeOption] qualifier types based upon
the contents of the receiver instance. For example attribute tags such
as ";lang-sl", ";binary", et al, are among the possible returns.
*/
func (r AttributeDescription) Options() (options []AttributeOption) {
	tsp := split(r.String(), `;`)
	for i := 0; i < len(tsp); i++ {
		// checkFilterOIDs enforces "keychar" ABNF.
		if err := checkFilterOIDs(tsp[i], ``); err == nil && i != 0 {
			options = append(options, AttributeTag(tsp[i]))
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
Note that this method is an alias of [AssertionValue.Escaped].
*/
func (r AssertionValue) String() string {
	return r.Escaped()
}

/*
Unescaped returns the unescaped receiver value. For example, "ジェシー"
is returned instead of "\e3\82\b8\e3\82\a7\e3\82\b7\e3\83\bc".
*/
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
func (r FilterAnd) String() (s string) {
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
func (r FilterOr) String() (s string) {
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
func (r FilterNot) String() (s string) {
	if !r.IsZero() {
		s = "(!" + r.Filter.String() + ")"
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterEqualityMatch) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterGreaterOrEqual) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `>=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterLessOrEqual) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `<=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterApproximateMatch) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `~=` + r.Value.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterPresent) String() (s string) {
	if !r.IsZero() {
		s = `(` + r.Desc.String() + `=*` + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterSubstrings) String() (s string) {
	if !r.IsZero() {
		s = `(` + string(r.Type) + `=` + r.Substrings.String() + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r FilterExtensibleMatch) String() (s string) {
	if !r.IsZero() {
		if r.MatchValue == nil {
			// always required here.
			return
		}

		value := r.MatchValue.String()
		typ := r.Type.String()
		mr := r.MatchingRule.String()
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
func (r FilterAnd) Choice() string { return "and" }

/*
Choice returns the string literal CHOICE "or".
*/
func (r FilterOr) Choice() string { return "or" }

/*
Choice returns the string literal CHOICE "not".
*/
func (r FilterNot) Choice() string { return "not" }

/*
Choice returns the string literal CHOICE "equalityMatch".
*/
func (r FilterEqualityMatch) Choice() string { return "equalityMatch" }

/*
Choice returns the string literal CHOICE "greaterOrEqual".
*/
func (r FilterGreaterOrEqual) Choice() string { return "greaterOrEqual" }

/*
Choice returns the string literal CHOICE "lessOrEqual".
*/
func (r FilterLessOrEqual) Choice() string { return "lessOrEqual" }

/*
Choice returns the string literal CHOICE "approxMatch".
*/
func (r FilterApproximateMatch) Choice() string { return "approxMatch" }

/*
Choice returns the string literal CHOICE "present".
*/
func (r FilterPresent) Choice() string { return "present" }

/*
Choice returns the string literal CHOICE "substrings".
*/
func (r FilterSubstrings) Choice() string { return "substrings" }

/*
Choice returns the string literal CHOICE "extensibleMatch".
*/
func (r FilterExtensibleMatch) Choice() string { return "extensibleMatch" }

// tag values are used for BER packet labeling
func (r invalidFilter) tag() uint64          { return 0 }
func (r FilterAnd) tag() uint64              { return 1 }
func (r FilterOr) tag() uint64               { return 2 }
func (r FilterNot) tag() uint64              { return 3 }
func (r FilterEqualityMatch) tag() uint64    { return 4 }
func (r FilterSubstrings) tag() uint64       { return 5 }
func (r FilterGreaterOrEqual) tag() uint64   { return 6 }
func (r FilterLessOrEqual) tag() uint64      { return 7 }
func (r FilterPresent) tag() uint64          { return 8 }
func (r FilterApproximateMatch) tag() uint64 { return 9 }
func (r FilterExtensibleMatch) tag() uint64  { return 10 }

func (r invalidFilter) Len() int { return 0 }

/*
Len returns the integer length of the receiver instance.
*/
func (r FilterAnd) Len() int { return len(r) }

/*
Len returns the integer length of the receiver instance.
*/
func (r FilterOr) Len() int { return len(r) }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterNot) Len() (l int) {
	if !r.IsZero() {
		l = r.Filter.Len()
	}

	return
}

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterEqualityMatch) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterGreaterOrEqual) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterLessOrEqual) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterApproximateMatch) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterPresent) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterSubstrings) Len() int { return 1 }

/*
Len always returns one (1), as instances of this kind only contain a
single value.
*/
func (r FilterExtensibleMatch) Len() int { return 1 }

func (r invalidFilter) Size() int { return 0 }

/*
Size returns the integer summation of the ASN.1 OCTET STRING tag (4) and the byte
size of the receiver instance
*/
func (r AssertionValue) Size() int { return len(r) + tagOctetString }

func (r AssertionValue) sizeTagged(tag uint64) int { return len(r) + int(tag) }

/*
Size returns the integer summation of the ASN.1 OCTET STRING tag (4) and the byte
size of the receiver instance
*/
func (r AttributeDescription) Size() int { return len(r) + tagOctetString }

func (r AttributeDescription) sizeTagged(tag uint64) int { return len(r) + int(tag) }

/*
Size returns the integer summation of the underlying [AttributeDescription] byte
size and the [FilterPresent] tag (8).
*/
func (r FilterPresent) Size() int {
	return r.Desc.Size() + int(r.tag())
}

/*
Size returns the integer summation of all underlying slice value sizes.
*/
func (r FilterAnd) Size() int {
	var size int
	if !r.IsZero() {
		for _, x := range r {
			size += x.Size()
		}
		size += sizeTagAndLength(int(r.tag()), size)
	}
	return size
}

/*
Size returns the integer summation of all underlying slice value sizes.
*/
func (r FilterOr) Size() int {
	var size int
	if !r.IsZero() {
		for _, x := range r {
			size += x.Size()
		}
		size += sizeTagAndLength(int(r.tag()), size)
	}
	return size
}

/*
Size returns the underlying [Filter] size value.
*/
func (r FilterNot) Size() int {
	var size int
	if !r.IsZero() {
		size = sizeTagAndLength(tagSequence, r.Filter.Size())
	}
	return size
}

/*
Size returns the integer summation of the underlying [AttributeDescription] and
[AttributeValue] byte sizes and the [FilterApproximateMatch] tag (9).
*/
func (r FilterApproximateMatch) Size() int {
	return AttributeValueAssertion(r).sizeTagged(r.tag())
}

/*
Size returns the integer summation of the underlying [AttributeDescription] and
[AttributeValue] byte sizes and the [FilterEqualityMatch] tag (4).
*/
func (r FilterEqualityMatch) Size() int {
	return AttributeValueAssertion(r).sizeTagged(r.tag())
}

/*
Size returns the integer summation of the underlying [AttributeDescription] and
[AttributeValue] byte sizes and the [FilterLessOrEqual] tag (7).
*/
func (r FilterLessOrEqual) Size() int {
	return AttributeValueAssertion(r).sizeTagged(r.tag())
}

/*
Size returns the integer summation of the underlying [AttributeDescription] and
[AttributeValue] byte sizes and the [FilterGreaterOrEqual] tag (6).
*/
func (r FilterGreaterOrEqual) Size() int {
	return AttributeValueAssertion(r).sizeTagged(r.tag())
}

/*
Size returns the integer summation of the underlying [AttributeDescription]
and [AttributeValue] byte sizes and the [FilterExtensibleMatch] tag (10).
*/
func (r FilterExtensibleMatch) Size() int {
	return MatchingRuleAssertion(r).sizeTagged(r.tag())
}

/*
Size returns the integer summation of the underlying value byte sizes
and their associated tags.
*/
func (r MatchingRuleAssertion) Size() int {
	return r.sizeTagged(tagSequence)
}

func (r MatchingRuleAssertion) IsZero() bool {
	return r.MatchingRule == nil &&
		len(r.Type) == 0 &&
		len(r.MatchValue) == 0 &&
		!r.DNAttributes
}

func (r MatchingRuleAssertion) sizeTagged(tag uint64) (size int) {
	if !r.IsZero() {
		if r.MatchingRule != nil {
			size += r.MatchingRule.sizeTagged(tagMatchingRuleAssertionMatchingRule)
		}
		if len(r.Type) > 0 {
			size += r.Type.sizeTagged(tagMatchingRuleAssertionType)
		}
		size += r.MatchValue.sizeTagged(tagMatchingRuleAssertionMatchValue)
		if r.DNAttributes {
			size += 1 + tagMatchingRuleAssertionDnAttributes
		}
		size += sizeTagAndLength(int(tag), size)
	}
	return
}

/*
Size returns the integer summation of the underlying value byte sizes
and their associated tags.
*/
func (r FilterSubstrings) Size() (size int) {
	return r.sizeTagged(tagSequence)
}

func (r FilterSubstrings) sizeTagged(tag int) (size int) {
	if !r.IsZero() {
		size += sizeTagAndLength(tagSequence, r.Substrings.Size())
		size += r.Type.Size()
		size += sizeTagAndLength(tag, size)
	}
	return
}

func parseSubFilter(x any) (filter Filter, err error) {
	var input string
	if input, err = assertString(x, 1, "Search Filter"); err != nil {
		return
	}

	if input = trimS(input); input == "" {
		filter = FilterPresent{Desc: AttributeDescription("objectClass")}
		return
	} else if cntns(input, `((`) || !checkParenBalanced(input) {
		err = endOfFilterErr
		filter = invalidFilter{}
		return
	}

	switch {
	case hasPfx(input, "(&"):
		filter, err = parseFilterAnd(input)
	case hasPfx(input, "(|"):
		filter, err = parseFilterOr(input)
	case hasPfx(input, "(!"):
		filter, err = parseFilterNot(input)
	default:
		filter, err = parseItemFilter(input)
	}

	return
}

func parseFilterAnd(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "&")
}

func parseFilterOr(input string) (Filter, error) {
	return parseComplexFilter(input[2:len(input)-1], "|")
}

func parseFilterNot(input string) (filter Filter, err error) {
	filter = invalidFilter{}
	if len(input) < 8 {
		err = invalidFilterErr
		return
	}

	var subRef Filter
	if subRef, err = parseSubFilter(input[2 : len(input)-1]); err == nil {
		filter = FilterNot{subRef}
	}

	return
}

func parseComplexFilter(input, prefix string) (Filter, error) {
	var refs []Filter
	parts := splitFilterParts(input)
	for _, part := range parts {
		subRef, err := parseSubFilter(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, subRef)
	}
	if prefix == "&" {
		return FilterAnd(refs), nil
	}
	return FilterOr(refs), nil
}

func parseItemFilter(input string) (filter Filter, err error) {
	filter = invalidFilter{}
	idx := stridx(input, "=")
	if idx == -1 {
		err = invalidFilterErr
		return
	}

	var cerr error // assertionValue character set errors

	pre, after := input[:idx], input[idx+1:]

	// Verify parenthetical encapsulation is balanced
	if err = checkParenEncaps(pre, after); err != nil {
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
		filter = FilterPresent{
			Desc: AttributeDescription(pre)}
	} else if hasSfx(pre, `>`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = FilterGreaterOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if hasSfx(pre, `<`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = FilterLessOrEqual{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if hasSfx(pre, `~`) {
		err = checkFilterOIDs(pre[:len(pre)-1], ``)
		cerr = assertionValueRunes(after, true)
		filter = FilterApproximateMatch{
			AttributeDescription(pre[:len(pre)-1]),
			AssertionValue(after)}
	} else if cntns(after, "*") {
		var ssa SubstringAssertion
		if ssa, err = marshalSubstringAssertion(after); err == nil {
			err = checkFilterOIDs(pre, ``)
			filter = FilterSubstrings{
				Type:       AttributeDescription(pre),
				Substrings: ssa}
		}
	} else if cntns(pre, ":") {
		filter, err = parseExtensibleMatch(pre, after)
		cerr = assertionValueRunes(after, true)
	} else {
		err = checkFilterOIDs(pre, ``)
		cerr = assertionValueRunes(after, true)
		filter = FilterEqualityMatch{
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
	_filter := FilterExtensibleMatch{}

	if !scol {
		if !valueIsDNAttrs(a) {
			if idx := idxr(a, ':'); idx != -1 {
				mr := trim(a[idx+1:], `:`)
				err = checkFilterOIDs(a[:idx], mr)
				_filter.Type = AttributeDescription(a[:idx])
				_filter.MatchingRule = MatchingRuleID(mr)
			}
		} else {
			_filter.DNAttributes = true
			if c := dnAttrSplit(a); len(c) == 2 {
				mr := trim(c[1], `:`)
				err = checkFilterOIDs(c[0], mr)
				if len(c[0]) > 0 && len(c[1]) > 0 {
					_filter.Type = AttributeDescription(c[0])
					_filter.MatchingRule = MatchingRuleID(mr)
				} else if len(c[0]) > 0 {
					_filter.Type = AttributeDescription(c[0])
					//} else if mr != "" {
					//_filter.MatchingRule = mr
				}
			}
		}
		_filter.MatchValue = val
	} else if scol {
		if sdn {
			_filter.DNAttributes = true
			_filter.MatchingRule = MatchingRuleID(a[4 : len(a)-1])
		} else {
			_filter.MatchingRule = MatchingRuleID(a[1 : len(a)-1])
		}
		err = checkFilterOIDs(``, _filter.MatchingRule.String())
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
func (r FilterAnd) BER() (packet *ber.Packet, err error) {
	if r.IsZero() || r.Len() == 0 {
		err = nilBEREncodeErr
		return
	}

	packet = ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		var child *ber.Packet
		if child, err = r[i].BER(); err == nil {
			packet.AppendChild(child)
		}
	}

	return

}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterOr) BER() (packet *ber.Packet, err error) {
	if r.IsZero() || r.Len() == 0 {
		err = nilBEREncodeErr
		return
	}

	packet = ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		child, err := r[i].BER()
		if err == nil {
			packet.AppendChild(child)
		}
	}

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterNot) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(r.tag()),
		nil,
		r.Choice())

	var not *ber.Packet
	if not, err = r.Filter.BER(); err == nil {
		packet.AppendChild(not)
	}

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterEqualityMatch) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.NewSequence(r.Choice())
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

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterApproximateMatch) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.NewSequence(r.Choice())
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

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterGreaterOrEqual) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.NewSequence(r.Choice())
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

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterLessOrEqual) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.NewSequence(r.Choice())
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

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterPresent) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.Encode(ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(r.tag()),
		r.Desc,
		r.Choice())

	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC4515.Filter] as the
input value.
*/
func (r FilterSubstrings) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = nilBEREncodeErr
		return
	}

	packet = ber.NewSequence(r.Choice())
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
	return
}

func unmarshalFilterPresentBER(packet *ber.Packet) (item Filter, err error) {
	if packet == nil {
		err = unknownBERPacket
	} else if str, ok := packet.Value.(AttributeDescription); !ok {
		item = invalidFilter{}
		err = errorTxt("Invalid or absent AttributeDescription; cannot unmarshal")
	} else {
		item = FilterPresent{Desc: AttributeDescription(str)}
	}

	return
}

func unmarshalGeLeFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	if packet == nil {
		err = unknownBERPacket
		return
	} else if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Ge/Le sequence fields (want:2); cannot unmarshal")
		return
	}

	typ := packet.Description
	atd := packet.Children[0]
	val := packet.Children[1]

	a, aok := atd.Value.(AttributeDescription)
	v, vok := val.Value.(AssertionValue)

	if !aok || !vok {
		err = errorTxt("Invalid or absent Ge/Le descr or value; cannot unmarshal")
	} else {
		if typ == "greaterOrEqual" {
			item = FilterGreaterOrEqual{Desc: AttributeDescription(a), Value: AssertionValue(v)}
		} else if typ == "lessOrEqual" {
			item = FilterLessOrEqual{Desc: AttributeDescription(a), Value: AssertionValue(v)}
		} else {
			err = errorTxt("Invalid or absent type identifier; cannot unmarshal")
		}
	}

	return
}

func unmarshalApproxFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	if packet == nil {
		err = unknownBERPacket
		return
	} else if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Approx sequence fields (want:2); cannot unmarshal")
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
		item = FilterApproximateMatch{Desc: AttributeDescription(a), Value: AssertionValue(v)}
	}

	return
}

func unmarshalExtensibleFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	var lct int
	if packet == nil {
		err = unknownBERPacket
		return
	} else if lct = len(packet.Children); !(1 <= lct && lct < 5) {
		err = errorTxt("Unexpected number of Extensible seq fields (want:1-4); cannot unmarshal")
		return
	}

	_item := FilterExtensibleMatch{}

	var val bool
	for i := 0; i < lct && _item.Choice() != "invalid"; i++ {
		child := packet.Children[i]
		var ok bool
		switch uint64(child.Tag) {
		case 1:
			if _item.MatchingRule, ok = child.Value.(MatchingRuleID); !ok {
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
	item = invalidFilter{}
	if packet == nil {
		err = unknownBERPacket
		return
	} else if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of Approx seq fields (want:2); cannot unmarshal")
		return
	}

	atd := packet.Children[0]
	val := packet.Children[1]

	a, aok := atd.Value.(AttributeDescription)
	v, vok := val.Value.(AssertionValue)

	if !aok || !vok {
		err = errorTxt("Invalid or absent Equality descr or value; cannot unmarshal")
	} else {
		item = FilterEqualityMatch{Desc: AttributeDescription(a), Value: AssertionValue(v)}
	}

	return
}

func unmarshalFilterSubstringsBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}
	if packet == nil {
		err = unknownBERPacket
		return
	} else if len(packet.Children) != 2 {
		err = errorTxt("Unexpected number of AttributeType instances (want:2); cannot unmarshal")
		return
	}

	at := packet.Children[0]
	ss := packet.Children[1]

	lct := len(ss.Children)
	if !(1 <= lct && lct < 4) {
		err = errorTxt("Unexpected number of AssertionValue instances (want 1-3); cannot unmarshal")
		return
	}

	_item := FilterSubstrings{
		Type:       at.Value.(AttributeDescription),
		Substrings: SubstringAssertion{},
	}

	var Any bool
	for i := 0; i < lct; i++ {
		child := ss.Children[i]
		switch uint64(child.Tag) {
		case 0:
			val := child.Value.(AssertionValue)
			_item.Substrings.Initial = AssertionValue(val)
		case 1:
			val := child.Value.(AssertionValue)
			_item.Substrings.Any = AssertionValue(val)
			Any = true
		case 2:
			val := child.Value.(AssertionValue)
			_item.Substrings.Final = AssertionValue(val)
		default:
			tn := fuint(uint64(child.Tag), 10)
			err = errorTxt("Unexpected BER tag: " + tn)
			break
		}
	}

	if !Any {
		err = errorTxt("Missing Substrings.Any assertion value; cannot unmarshal")
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
func (r FilterExtensibleMatch) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, nilBEREncodeErr
	}

	packet := ber.NewSequence(r.Choice())

	if len(r.MatchValue) > 0 {
		packet.AppendChild(ber.Encode(
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
	return nil, nilBEREncodeErr
}

// Verify parenthetical encapsulation is balanced
func checkParenEncaps(a, b string) (err error) {
	lencap := hasPfx(a, `(`)
	rencap := hasSfx(b, `)`)
	if lencap && !rencap {
		err = endOfFilterErr
	} else if !lencap && rencap {
		err = endOfFilterErr
	}

	return
}

func checkParenBalanced(x string) bool {
	return strcnt(x, `(`) == strcnt(x, `)`)
}

func checkFilterOIDs(t, m string) (err error) {
	r := RFC4512{}
	if len(t) > 0 {
		tsp := split(t, `;`) // we'll want to disregard tags
		if err = r.OID(tsp[0]); err != nil {
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
		err = unknownBERPacket
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
		filter, err = unmarshalFilterNotBER(packet)
	case "and", "or":
		filter, err = unmarshalSetFilterBER(packet)
	default:
		err = unknownBERPacket

	}

	return
}

func unmarshalItemFilterBER(packet *ber.Packet) (item Filter, err error) {
	item = invalidFilter{}

	switch packet.Description {
	case "equalityMatch":
		item, err = unmarshalEqualityFilterBER(packet)
	case "present":
		item, err = unmarshalFilterPresentBER(packet)
	case "substrings":
		item, err = unmarshalFilterSubstringsBER(packet)
	case "approxMatch":
		item, err = unmarshalApproxFilterBER(packet)
	case "lessOrEqual", "greaterOrEqual":
		item, err = unmarshalGeLeFilterBER(packet)
	case "extensibleMatch":
		item, err = unmarshalExtensibleFilterBER(packet)
	default:
		err = unknownBERPacket
	}

	return
}

func unmarshalSetFilterBER(packet *ber.Packet) (filter Filter, err error) {
	lct := len(packet.Children)
	filter = invalidFilter{}

	var filters []Filter
	and := packet.Description == "and"

	if lct == 0 || packet.Description == "invalid" || !(and || packet.Description == "or") {
		err = emptyFilterSetErr
		return
	}

	for i := 0; i < lct && err == nil; i++ {
		child := packet.Children[i]
		var subfilter Filter
		if subfilter, err = unmarshalFilterBER(child); err == nil {
			filters = append(filters, subfilter)
		}
	}

	if err == nil {
		if and {
			filter = FilterAnd(filters)
		} else {
			filter = FilterOr(filters)
		}
	}

	return
}

func unmarshalFilterNotBER(packet *ber.Packet) (filter Filter, err error) {
	filter = invalidFilter{}
	if len(packet.Children) != 1 {
		err = invalidFilterErr
		return
	}

	var nest Filter
	if nest, err = unmarshalFilterBER(packet.Children[0]); err == nil {
		filter = FilterNot{nest}
	}

	return
}

func valueIsDNAttrs(x string) bool {
	return cntns(x, `:dn:`) || cntns(x, `:DN:`)
}

func dnAttrSplit(x string) (slice []string) {
	lo := cntns(x, `:dn:`)
	hi := cntns(x, `:DN:`)
	if lo && !hi {
		slice = split(x, `:dn:`)
	} else if !lo && hi {
		slice = split(x, `:DN:`)
	}

	return
}

const (
	tagMatchingRuleAssertionMatchingRule = 1
	tagMatchingRuleAssertionType         = 2
	tagMatchingRuleAssertionMatchValue   = 3
	tagMatchingRuleAssertionDnAttributes = 4
)
