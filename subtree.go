package dirsyn

/*
subtree.go implements the RFC3672 SubtreeSpecification.
*/

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
SubtreeSpecification implements the Subtree Specification construct.

At present, instances of this type are not ASN.1 encode-friendly due
to the use of an interface type for [Refinement] instances. This is
because Go's [encoding/asn1] package does not play nicely with such
types.

A zero instance of this type is equal to "{}" when represented as a
string value, which is a valid default value when populated for an
entry's "[subtreeSpecification]" attribute type instance within a DIT.

From [§ 2.1 of RFC 3672]:

	SubtreeSpecification ::= SEQUENCE {
	    base                [0] LocalName DEFAULT { },
	                            COMPONENTS OF ChopSpecification,
	    specificationFilter [4] Refinement OPTIONAL }

	LocalName ::= RDNSequence

	ChopSpecification ::= SEQUENCE {
	    specificExclusions  [1] SET OF CHOICE {
	                            chopBefore [0] LocalName,
	                            chopAfter [1] LocalName } OPTIONAL,
	    minimum             [2] BaseDistance DEFAULT 0,
	    maximum             [3] BaseDistance OPTIONAL }

	BaseDistance ::= INTEGER (0 .. MAX)

	Refinement ::= CHOICE {
	    item                [0] OBJECT-CLASS.&id,
	    and                 [1] SET OF Refinement,
	    or                  [2] SET OF Refinement,
	    not                 [3] Refinement }

From [Appendix A of RFC 3672]:

	SubtreeSpecification = "{" [ sp ss-base ]
	                           [ sep sp ss-specificExclusions ]
	                           [ sep sp ss-minimum ]
	                           [ sep sp ss-maximum ]
	                           [ sep sp ss-specificationFilter ]
	                                sp "}"

	ss-base                = id-base                msp LocalName
	ss-specificExclusions  = id-specificExclusions  msp SpecificExclusions
	ss-minimum             = id-minimum             msp BaseDistance
	ss-maximum             = id-maximum             msp BaseDistance
	ss-specificationFilter = id-specificationFilter msp Refinement

	BaseDistance = INTEGER-0-MAX

From [§ 6 of RFC 3642]:

	LocalName         = RDNSequence
	RDNSequence       = dquote *SafeUTF8Character dquote

	INTEGER-0-MAX   = "0" / positive-number
	positive-number = non-zero-digit *decimal-digit

	sp  =  *%x20  ; zero, one or more space characters
	msp = 1*%x20  ; one or more space characters
	sep = [ "," ]

	OBJECT-IDENTIFIER = numeric-oid / descr
	numeric-oid       = oid-component 1*( "." oid-component )
	oid-component     = "0" / positive-number

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
[subtreeSpecification]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.3
[§ 2.1 of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.1
[§ 6 of RFC 3642]: https://datatracker.ietf.org/doc/html/rfc3642#section-6
*/
type SubtreeSpecification struct {
	Base LocalName `asn1:"tag:0,default:"`

	// COMPONENTS OF chopSpecification
	ChopSpecification

	SpecificationFilter Refinement `asn1:"tag:4,optional"`
}

/*
SubtreeSpecification returns an instance of [SubtreeSpecification]
alongside an error.

If the input is nil, the default [SubtreeSpecification] (e.g.: "{}")
is returned.

If the input is a string, an attempt to marshal the value is made. If
the string is zero, this is equivalent to providing nil.

If the input is a *[ber.Packet] instance, it is unmarshaled into the
return instance of [SubtreeSpecification].

Any errors found will result in the return of an invalid [Filter] instance.
*/
func (r RFC3672) SubtreeSpecification(x any) (ss SubtreeSpecification, err error) {

	var raw string
	switch tv := x.(type) {
	case nil:
		return
	case *ber.Packet:
		ss, err = unmarshalSubtreeSpecificationBER(tv)
		return
	default:
		if raw, err = assertString(x, 0, "Subtree Specification"); err != nil {
			return
		} else if raw == "" {
			return // no error
		}
	}

	if err = checkSubtreeEncaps(raw); err != nil {
		return
	}
	raw = trimS(raw[1 : len(raw)-1])

	var ranges map[string][]int = make(map[string][]int, 0)

	var pos int
	if begin := stridx(raw, `base `); begin != -1 {
		var end int
		begin += 5
		if ss.Base, end, err = subtreeBase(raw[begin:]); err != nil {
			return
		}
		pos += begin
		end += pos + 1
		ranges[`base`] = []int{begin, end}
	}

	if begin := stridx(raw, `specificExclusions `); begin != -1 {
		var end int
		begin += 19
		if ss.ChopSpecification.Exclusions, end, err = subtreeExclusions(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`specificExclusions`] = []int{begin, end}
	}

	if begin := stridx(raw, `minimum `); begin != -1 {
		var end int
		begin += 8
		if ss.ChopSpecification.Minimum, end, err = subtreeMinMax(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`minimum`] = []int{begin, end}
	}

	if begin := stridx(raw, `maximum `); begin != -1 {
		var end int
		begin += 8
		if ss.ChopSpecification.Maximum, end, err = subtreeMinMax(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`maximum`] = []int{begin, end}
	}

	if begin, end := ss.processSpecFilter(raw); begin > -1 {
		ranges[`specificationFilter`] = []int{begin, end}
	}

	return
}

func (r *SubtreeSpecification) processSpecFilter(raw string) (begin, end int) {
	end = -1
	if begin = stridx(raw, `specificationFilter `); begin != -1 {
		begin += 20
		var err error
		if r.SpecificationFilter, err = subtreeRefinement(raw, begin); err == nil {
			end = begin + len(raw) - begin
		}
	}

	return
}

func checkSubtreeEncaps(raw string) (err error) {
	if raw[0] != '{' || raw[len(raw)-1] != '}' {
		err = errorTxt("SubtreeSpecification {} encapsulation error")
	}
	return
}

/*
BER returns the BER encoding of the receiver instance alongside an error.

To decode the return *[ber.Packet], pass it to [RFC3672.SubtreeSpecification]
as the   input value.
*/
func (r SubtreeSpecification) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return ber.NewSequence(`SubtreeSpecification`), nil
	}

	packet := ber.NewSequence(`SubtreeSpecification`)

	if !r.Base.IsZero() {
		packet.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypeConstructed,
			ber.Tag(0),
			r.Base.String(),
			`base`))
	}

	if !r.ChopSpecification.IsZero() {
		child, err := r.ChopSpecification.BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	// SpecFilter is an interface, check nil.
	if r.SpecificationFilter != nil {
		child, err := r.SpecificationFilter.BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	return packet, nil
}

/*
SpecificExclusions implements the chopSpecification specificExclusions ASN.1
SET OF CHOICE component.

From [Appendix A of RFC 3672]:

	SpecificExclusions = "{" [ sp SpecificExclusion *( "," sp SpecificExclusion ) ] sp "}"

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
*/
type SpecificExclusions []SpecificExclusion

func (r SpecificExclusions) Len() int {
	return len(r)
}

/*
SpecificExclusion implements the chopSpecification specificExclusion component.

From [§ 2.1 of RFC3672]:

	        LocalName ::= RDNSequence

		SET OF CHOICE {
	   	   chopBefore [0] LocalName,
	           chopAfter  [1] LocalName }

From [Appendix A of RFC 3672]:

	SpecificExclusion  = chopBefore / chopAfter
	chopBefore         = id-chopBefore ":" LocalName
	chopAfter          = id-chopAfter  ":" LocalName
	id-chopBefore      = %x63.68.6F.70.42.65.66.6F.72.65 ; "chopBefore"
	id-chopAfter       = %x63.68.6F.70.41.66.74.65.72    ; "chopAfter"

[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A

[§ 2.1 of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#section-2.1
*/
type SpecificExclusion struct {
	ChopBefore LocalName `asn1:"tag:0"`
	ChopAfter  LocalName `asn1:"tag:1"`
}

/*
ChopSpecification implements the chopSpecification component of an
instance of [SubtreeSpecification].
*/
type ChopSpecification struct {
	Exclusions SpecificExclusions `asn1:"tag:1,optional"`
	Minimum    BaseDistance       `asn1:"tag:2,default:0"`
	Maximum    BaseDistance       `asn1:"tag:3,optional"`
}

func (r ChopSpecification) IsZero() bool {
	return len(r.Exclusions) == 0 &&
		r.Minimum == 0 &&
		r.Maximum == 0
}

func (r ChopSpecification) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil ChopSpecification, cannot BER encode")
	}

	packet := ber.NewSequence(`ChopSpecification`)

	if r.Exclusions.Len() > 0 {
		child, err := r.Exclusions.BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	packet.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(2),
		int(r.Minimum),
		`minimum`))
	packet.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(3),
		int(r.Maximum),
		`maximum`))

	return packet, nil
}

/*
BaseDistance implements the integer value of a minimum and/or maximum
[SubtreeSpecification] depth refinement parameter. An instance of this
type for either use case indicates the subordinate entry depth "range"
whose contents are subject to the influence of the [SubtreeSpecification]
bearing a non-zero value.

A zero instance of this type, unsurprisingly, is zero (0) and indicates
no depth refinement is in force for the respective administrative area.
*/
type BaseDistance int

/*
LocalName implements an "RDNSequence" per [§ 6 of RFC 3642].

Instances of this type may be found within the "base" of a [SubtreeSpecification]
instance, as well as the "name" of a [SpecificExclusion], and are used to describe
an indicated entry set present at, or within, a given administrative area.

A zero instance of this type is equivalent to a null DN, which normally indicates
that the given administrative area is defined by the current subentry.

[§ 6 of RFC 3642]: https://datatracker.ietf.org/doc/html/rfc3642#section-6
*/
type LocalName string

/*
String returns the string representation of the receiver instance.
*/
func (r LocalName) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LocalName) IsZero() bool {
	return r == ``
}

func (r SpecificExclusions) IsZero() bool {
	return len(r) == 0
}

/*
String returns the string representation of the receiver instance.
*/
func (r SpecificExclusions) String() string {
	if len(r) == 0 {
		return `{ }`
	}

	var _s []string
	for i := 0; i < len(r); i++ {
		_s = append(_s, r[i].String())
	}

	return `{ ` + join(_s, `, `) + ` }`
}

func (r SpecificExclusions) BER() (*ber.Packet, error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Exclusions; cannot BER encode")
	}

	packet := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(1),
		nil,
		`specificExclusions`)

	for i := 0; i < r.Len(); i++ {
		child, err := r[i].BER()
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
	}

	return packet, nil

}

func (r SpecificExclusion) IsZero() bool {
	return &r == nil
}

/*
String returns the string literal "before" or "after" as the selected
ASN.1 CHOICE. The determination is made based upon non-zeroness of the
respective [LocalName] value. A zero string is returned if the instance
is invalid.
*/
func (r SpecificExclusion) Choice() (se string) {
	if chopB := r.ChopBefore.String(); chopB != "" {
		se = `before`
	} else if chopA := r.ChopAfter.String(); chopA != "" {
		se = `after`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r SpecificExclusion) String() (s string) {
	choice := r.Choice()
	if choice == "before" {
		s = `chopBefore ` + `"` + r.ChopBefore.String() + `"`
	} else if choice == "after" {
		s = `chopAfter ` + `"` + r.ChopAfter.String() + `"`
	}

	return
}

func (r SpecificExclusion) BER() (*ber.Packet, error) {
	if r.IsZero() || r.Choice() == "" {
		return nil, errorTxt("Nil SpecificExclusion, cannot BER encode")
	}

	var (
		tag  uint64
		val  string
		desc string
	)

	if r.Choice() == `after` {
		tag = uint64(1)
		desc = `chopAfter`
		val = r.ChopAfter.String()
	} else {
		desc = `chopBefore`
		val = r.ChopBefore.String()
	}

	return ber.NewString(
		ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(tag),
		val,
		desc), nil
}

func subtreeExclusions(raw string, begin int) (excl SpecificExclusions, end int, err error) {
	end = -1

	if raw[begin] != '{' {
		err = errorTxt("Bad exclusion encapsulation")
		return
	}

	var pos int
	if pos, end, err = deconstructExclusions(raw, begin); err != nil {
		return
	}

	values := fields(raw[pos:end])

	for i := 0; i < len(values); i += 2 {
		var ex SpecificExclusion
		if !strInSlice(values[i], []string{`chopBefore`, `chopAfter`}) {
			err = errorTxt("Unexpected key '" + values[i] + "'")
			break

		}
		after := values[i] == `chopAfter`

		localName := trim(trimR(values[i+1], `,`), `"`)
		if err = isSafeUTF8(localName); err == nil {
			if after {
				ex.ChopAfter = LocalName(localName)
			} else {
				ex.ChopBefore = LocalName(localName)
			}
			excl = append(excl, ex)
		}
	}

	return
}

func deconstructExclusions(raw string, begin int) (pos, end int, err error) {
	pos = -1
	if idx := stridx(raw[begin:], `chop`); idx != -1 {
		var (
			before int = -1
			after  int = -1
		)

		if hasPfx(raw[begin+idx+4:], `Before`) {
			before = begin + idx
		}

		if hasPfx(raw[begin+idx+4:], `After`) {
			after = begin + idx
		}

		if after == -1 && before > after {
			pos = before
		} else if before == -1 && before < after {
			pos = after
		}
	}

	if pos == -1 {
		err = errorTxt("No chop directive found in value")
		return
	}

	for i, char := range raw[pos:] {
		switch char {
		case '}':
			end = pos + i
			break
		}
	}

	return
}

func subtreeMinMax(raw string, begin int) (minmax BaseDistance, end int, err error) {
	end = -1

	var (
		max string
		m   int
	)

	for i := 0; i < len(raw[begin:]); i++ {
		if isDigit(rune(raw[begin+i])) {
			max += string(raw[begin+i])
			continue
		}
		break
	}

	if m, err = atoi(max); err == nil {
		minmax = BaseDistance(m)
		end = len(max)
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r SubtreeSpecification) IsZero() bool {
	return r.Base == "" &&
		r.ChopSpecification.IsZero() &&
		r.SpecificationFilter == nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r SubtreeSpecification) String() (s string) {
	if r.IsZero() {
		s = `{}`
		return
	}

	var _s []string
	if len(r.Base) > 0 {
		_s = append(_s, `base `+`"`+string(r.Base)+`"`)
	}

	if x := r.ChopSpecification.Exclusions; len(x) > 0 {
		_s = append(_s, `specificExclusions `+x.String())
	}

	if r.ChopSpecification.Minimum > 0 {
		_s = append(_s, `minimum `+itoa(int(r.ChopSpecification.Minimum)))

	}

	if r.ChopSpecification.Maximum > 0 {
		_s = append(_s, `maximum `+itoa(int(r.ChopSpecification.Maximum)))

	}

	if r.SpecificationFilter != nil {
		x := r.SpecificationFilter.String()
		_s = append(_s, `specificationFilter `+x)
	}

	s = `{` + join(_s, `, `) + `}`

	return
}

/*
Refinement implements [Appendix A of RFC 3672], and serves as the
"SpecificationFilter" optionally found within a Subtree Specification.
It is qualified through instances of:

  - [ItemRefinement]
  - [AndRefinement]
  - [OrRefinement]
  - [NotRefinement]

From [Appendix A of RFC 3672]:

	Refinement  = item / and / or / not
	item        = id-item ":" OBJECT-IDENTIFIER
	and         = id-and  ":" Refinements
	or          = id-or   ":" Refinements
	not         = id-not  ":" Refinement

	Refinements = "{" [ sp Refinement *( "," sp Refinement ) ] sp "}"
	id-item     = %x69.74.65.6D ; "item"
	id-and      = %x61.6E.64    ; "and"
	id-or       = %x6F.72       ; "or"
	id-not      = %x6E.6F.74    ; "not"

From [ITU-T Rec. X.501 clause 12.3.5]:

	Refinement ::= CHOICE {
		item [0] OBJECT-CLASS.&id,
		and  [1] SET SIZE (1..MAX) OF Refinement,
		or   [2] SET SIZE (1..MAX) OF Refinement,
		not  [3] Refinement,
		... }

[ITU-T Rec. X.501 clause 12.3.5]: https://www.itu.int/rec/T-REC-X.501
[Appendix A of RFC 3672]: https://datatracker.ietf.org/doc/html/rfc3672#appendix-A
*/
type Refinement interface {
	// BER returns the BER encoding of the receiver
	// instance alongside an error.
	BER() (*ber.Packet, error)

	// Index returns the Nth slice index found within
	// the receiver instance. This is only useful if
	// the receiver is an AndRefinement or OrRefinement
	// Refinement qualifier type instance.
	Index(int) Refinement

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
	// an AndRefinement or OrRefinement Refinement
	// qualifier type instance.
	Len() int

	// differentiate Refinement from other interfaces
	isRefinement()
}

/*
AndRefinement implements slices of [Refinement], all of which are expected to
evaluate as true during processing.

Instances of this type qualify the [Refinement] interface type.
*/
type AndRefinement []Refinement

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AndRefinement) IsZero() bool {
	return &r == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r OrRefinement) IsZero() bool {
	return &r == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NotRefinement) IsZero() bool {
	return r.Refinement == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ItemRefinement) IsZero() bool {
	return string(r) == ""
}

/*
String returns the string representation of the receiver instance.
*/
func (r AndRefinement) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "and:{" + join(parts, ",") + "}"
	}

	return
}

/*
Type returns the string literal "and" as the ASN.1 CHOICE.
*/
func (r AndRefinement) Choice() string {
	return "and"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r AndRefinement) Len() int {
	return len(r)
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r AndRefinement) Index(idx int) (x Refinement) {
	rl := r.Len()
	x = invalidRefinement{}
	if 0 <= idx && idx < rl {
		x = r[idx]
	}

	return
}

/*
OrRefinement implements slices of [Refinement], at least one of which is
expected to evaluate as true during processing.

Instances of this type qualify the [Refinement] interface type.
*/
type OrRefinement []Refinement

/*
String returns the string representation of the receiver instance.
*/
func (r OrRefinement) String() (s string) {
	if !r.IsZero() {
		var parts []string
		for _, ref := range r {
			parts = append(parts, ref.String())
		}
		s = "or:{" + join(parts, ",") + "}"
	}

	return
}

/*
Type returns the string literal "or" as the ASN.1 CHOICE.
*/
func (r OrRefinement) Choice() string {
	return "or"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r OrRefinement) Len() int {
	return len(r)
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r OrRefinement) Index(idx int) (x Refinement) {
	rl := r.Len()
	x = invalidRefinement{}
	if 0 <= idx && idx < rl {
		x = r[idx]
	}

	return
}

/*
NotRefinement implements a negated, recursive instance of [Refinement].
Normally during processing, instances of this type are processed first
when present among other qualifiers as siblings (slices), such as with
[AndRefinement] and [OrRefinement] instances.

Instances of this type qualify the [Refinement] interface type.
*/
type NotRefinement struct {
	Refinement
}

/*
String returns the string representation of the receiver instance.
*/
func (r NotRefinement) String() string {
	if r.IsZero() {
		return ``
	}

	return "not:" + r.Refinement.String()
}

/*
Type returns the string literal "not" as the ASN.1 CHOICE.
*/
func (r NotRefinement) Choice() string {
	return "not"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r NotRefinement) Len() (l int) {
	if !r.IsZero() {
		l = r.Refinement.Len()
	}

	return
}

/*
Index returns the Nth slice index found within the receiver instance.
*/
func (r NotRefinement) Index(idx int) (x Refinement) {
	x = invalidRefinement{}

	if !r.IsZero() {
		x = r.Refinement.Index(idx)
	}

	return
}

func (r OrRefinement) isRefinement()   {}
func (r AndRefinement) isRefinement()  {}
func (r NotRefinement) isRefinement()  {}
func (r ItemRefinement) isRefinement() {}

type invalidRefinement struct{}

func (r invalidRefinement) isRefinement()          {}
func (r invalidRefinement) String() string         { return `` }
func (r invalidRefinement) IsZero() bool           { return false }
func (r invalidRefinement) Len() int               { return 0 }
func (r invalidRefinement) Index(_ int) Refinement { return invalidRefinement{} }
func (r invalidRefinement) Choice() string         { return `invalid` }
func (r invalidRefinement) BER() (*ber.Packet, error) {
	return nil, errorTxt("Nil Refinement, cannot BER encode")
}

/*
ItemRefinement implements the core ("atom") value type to be used in
[Refinement] statements, and appears in [AndRefinement], [OrRefinement]
and [NotRefinement] [Refinement] qualifier type instances.

This is the only "tangible" type in the "specificationFilter" formula,
as all other types simply act as contextual "envelopes" meant to,
ultimately, store instances of this type.

Instances of this type qualify the [Refinement] interface type.
*/
type ItemRefinement string

/*
String returns the string representation of the receiver instance.
*/
func (r ItemRefinement) String() (s string) {
	if !r.IsZero() {
		s = `item:` + string(r)
	}

	return
}

/*
Type returns the string literal "item" as the ASN.1 CHOICE.
*/
func (r ItemRefinement) Choice() string {
	return "item"
}

/*
Len always returns the integer 1 (one).  This method only exists to satisfy
Go's interface signature requirements.
*/
func (r ItemRefinement) Len() int {
	return 1
}

/*
Index returns the receiver instance of [Refinement]. This method only
exists to satisfy Go's interface signature requirement.
*/
func (r ItemRefinement) Index(_ int) Refinement {
	return r
}

func subtreeBase(x any) (base LocalName, end int, err error) {
	end = -1
	var raw string
	if raw, err = assertString(x, 1, "Subtree Base"); err != nil {
		return
	}

	// FIXME - extend spec to allow single quotes?
	if raw[0] != '"' {
		err = errorTxt("Missing encapsulation (\") for LocalName")
		return
	}

	for i := 1; i < len(raw) && end == -1; i++ {
		switch char := rune(raw[i]); char {
		case '"':
			end = i
			break
		}
	}

	if err = isSafeUTF8(raw[1:end]); err == nil {
		base = LocalName(raw[1:end])
	}

	return
}

func subtreeRefinement(x any, begin ...int) (ref Refinement, err error) {
	var input string
	if input, err = assertString(x, 1, "Specification Filter"); err != nil {
		return
	}
	if len(begin) > 0 {
		input = trimS(input[begin[0]:])
	} else {
		input = trimS(input)
	}

	if hasPfx(input, "item:") {
		ref, err = parseItem(input)
	} else if hasPfx(input, "and:") {
		ref, err = parseAnd(input)
	} else if hasPfx(input, "or:") {
		ref, err = parseOr(input)
	} else if hasPfx(input, "not:") {
		ref, err = parseNot(input)
	} else {
		err = newErr("invalid refinement: " + input)
	}

	return
}

func parseItem(input string) (Refinement, error) {
	parts := splitN(input, ":", 2)
	if len(parts) != 2 {
		return nil, newErr("invalid item: " + input)
	}
	return ItemRefinement(parts[1]), nil
}

func parseAnd(input string) (Refinement, error) {
	return parseComplexRefinement(input, "and:")
}

func parseOr(input string) (Refinement, error) {
	return parseComplexRefinement(input, "or:")
}

func parseNot(input string) (Refinement, error) {
	input = trimPfx(input, "not:")
	subRef, err := subtreeRefinement(input)
	if err != nil {
		return nil, err
	}
	return NotRefinement{subRef}, nil
}

func parseComplexRefinement(input, prefix string) (Refinement, error) {
	input = trimPfx(input, prefix)
	input = trimS(input)
	input = trimPfx(input, "{")
	input = trimSfx(input, "}")

	var refs []Refinement
	parts := splitRefinementParts(input)
	for _, part := range parts {
		subRef, err := subtreeRefinement(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, subRef)
	}

	if prefix == "and:" {
		return AndRefinement(refs), nil
	}
	return OrRefinement(refs), nil
}

func splitRefinementParts(input string) []string {
	var parts []string
	currentPart := newStrBuilder()
	depth := 0

	for _, char := range input {
		if char == '{' {
			depth++
		} else if char == '}' {
			depth--
		}

		if char == ',' && depth == 0 {
			parts = append(parts, trimS(currentPart.String()))
			currentPart.Reset()
		} else {
			currentPart.WriteRune(char)
		}
	}

	if currentPart.Len() > 0 {
		parts = append(parts, trimS(currentPart.String()))
	}

	return parts
}

/*
BER returns the BER encoding of the receiver instance.
*/
func (r ItemRefinement) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		err = errorTxt("Nil Refinement; cannot BER encode")
		return
	}

	packet = ber.NewSequence(`Refinement`)
	packet.Tag = ber.Tag(4)
	packet.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(0),
		string(r),
		`item`))

	return
}

/*
BER returns the BER encoding of the receiver instance.
*/
func (r AndRefinement) BER() (packet *ber.Packet, err error) {
	if r.IsZero() || r.Len() == 0 {
		err = errorTxt("Nil Refinement, cannot BER encode")
		return
	}

	packet = ber.NewSequence(`Refinement`)
	packet.Tag = ber.Tag(4)
	set := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(1),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		var child *ber.Packet
		if child, err = r[i].BER(); err != nil {
			return
		}
		set.AppendChild(child)
	}

	packet.AppendChild(set)

	return
}

/*
BER returns the BER encoding of the receiver instance.
*/
func (r OrRefinement) BER() (packet *ber.Packet, err error) {
	if r.IsZero() || r.Len() == 0 {
		err = errorTxt("Nil Refinement, cannot BER encode")
		return
	}

	packet = ber.NewSequence(`Refinement`)
	packet.Tag = ber.Tag(4)
	set := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(1),
		nil,
		r.Choice())

	for i := 0; i < r.Len(); i++ {
		var child *ber.Packet
		if child, err = r[i].BER(); err != nil {
			return
		}
		set.AppendChild(child)
	}

	packet.AppendChild(set)

	return
}

/*
BER returns the BER encoding of the receiver instance.
*/
func (r NotRefinement) BER() (packet *ber.Packet, err error) {
	if r.IsZero() {
		return nil, errorTxt("Nil Refinement, cannot BER encode")
	}

	packet = ber.NewSequence(`Refinement`)
	packet.Tag = ber.Tag(4)
	inner := ber.Encode(ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(3),
		nil,
		r.Choice())

	not, err := r.Refinement.BER()
	if err == nil {
		inner.AppendChild(not)
		packet.AppendChild(inner)
	}

	return packet, err
}

func unmarshalSubtreeSpecificationBER(packet *ber.Packet) (ss SubtreeSpecification, err error) {
	if packet == nil {
		err = errorTxt("Nil SubtreeSpecification BER packet; cannot unmarshal")
		return
	}
	lc := len(packet.Children)

	for i := 0; i < lc && err == nil; i++ {
		child := packet.Children[i]
		switch uint64(child.Tag) {
		case 0:
			// Base
			var ln string
			var ok bool
			if ln, ok = child.Value.(string); !ok {
				err = errorTxt("Failed to unmarshal base RDNSequence")
				break
			}
			ss.Base = LocalName(ln)
		case 4:
			// Refinement
			var ref Refinement
			if ref, err = unmarshalRefinementBER(child); err == nil {
				ss.SpecificationFilter = ref
			}
		default:
			// ChopSpecification ... maybe
			if child.Description == "ChopSpecification" {
				var chop ChopSpecification
				if chop, err = unmarshalChopSpecificationBER(child); err == nil {
					ss.ChopSpecification = chop
				}
			} else {
				err = errorTxt("Unknown child packet (want:ChopSpecification); cannot unmarshal")
			}
		}
	}

	return
}

func unmarshalNotRefinementBER(packet *ber.Packet) (not Refinement, err error) {
	not = invalidRefinement{}
	if len(packet.Children) != 1 {
		err = errorTxt("Invalid Not Refinement (no payload); cannot unmarshal")
		return
	}

	var nest Refinement
	if nest, err = unmarshalRefinementBER(packet.Children[0]); err == nil {
		not = NotRefinement{nest}
	}

	return
}

func unmarshalRefinementBER(packet *ber.Packet) (refinement Refinement, err error) {
	refinement = invalidRefinement{}
	if packet == nil || len(packet.Children) != 1 {
		err = errorTxt("Nil BER packet; cannot unmarshal")
		return
	}

	refpkt := packet.Children[0]

	switch refpkt.Description {
	case "item":
		refinement, err = unmarshalItemRefinementBER(refpkt)
	case "not":
		refinement, err = unmarshalNotRefinementBER(refpkt)
	case "and", "or":
		refinement, err = unmarshalSetRefinementBER(refpkt)
	default:
		err = errorTxt("Unidentified BER packet; cannot unmarshal to Refinement")

	}

	return
}

func unmarshalItemRefinementBER(packet *ber.Packet) (item Refinement, err error) {

	v, vok := packet.Value.(string)
	if !vok {
		err = errorTxt("Invalid or absent item refinement objectClass ID; cannot unmarshal")
	} else {
		item = ItemRefinement(v)
	}

	return
}

func unmarshalSetRefinementBER(packet *ber.Packet) (refinement Refinement, err error) {
	lc := len(packet.Children)
	refinement = invalidRefinement{}

	var refs []Refinement
	and := packet.Description == "and"

	if lc == 0 || packet.Description == "invalid" || !(and || packet.Description == "or") {
		err = errorTxt("No Refinement qualifiers present within set packet; cannot unmarshal")
		return
	}

	for i := 0; i < lc && err == nil; i++ {
		child := packet.Children[i]
		var subref Refinement
		if subref, err = unmarshalRefinementBER(child); err == nil {
			refs = append(refs, subref)
		}
	}

	if and {
		refinement = AndRefinement(refs)
	} else {
		refinement = OrRefinement(refs)
	}

	return
}

func unmarshalChopSpecificationBER(packet *ber.Packet) (chop ChopSpecification, err error) {
	lc := len(packet.Children)
	if !(1 <= lc && lc < 4) {
		err = errorTxt("Unexpected number of ChopSpecification fields (want:1-3); cannot unmarshal")
		return
	}

	for i := 0; i < lc && err == nil; i++ {
		child := packet.Children[i]
		switch uint64(child.Tag) {
		case 1:
			// Exclusions
			var ses SpecificExclusions
			if ses, err = unmarshalExclusionsBER(child); err == nil {
				chop.Exclusions = ses
			}
		case 2:
			// Minimum base distance
			if min, _ := child.Value.(int); min > 0 {
				chop.Minimum = BaseDistance(min)
			}
		case 3:
			// Maximum base distance
			if max, _ := child.Value.(int); max > 0 {
				chop.Maximum = BaseDistance(max)
			}
		default:
			// bogus tag
			err = errorTxt("Unknown ChopSpecification tag (want:1-3); cannot unmarshal")
		}
	}

	return
}

func unmarshalExclusionsBER(packet *ber.Packet) (ses SpecificExclusions, err error) {
	lc := len(packet.Children)

	var _ses SpecificExclusions
	for i := 0; i < lc && err == nil; i++ {
		child := packet.Children[i]
		var se SpecificExclusion
		if se, err = unmarshalExclusionBER(child); err == nil {
			_ses = append(_ses, se)
		}
	}

	if err == nil {
		ses = _ses
	}

	return
}

func unmarshalExclusionBER(packet *ber.Packet) (se SpecificExclusion, err error) {
	if packet.Description == "chopBefore" {
		se.ChopBefore = LocalName(packet.Value.(string))
	} else if packet.Description == "chopAfter" {
		se.ChopAfter = LocalName(packet.Value.(string))
	} else {
		err = errorTxt("Unidentified SpecificExclusion (want:chopBefore|chopAfter); cannot unmarshal")
	}

	return
}
