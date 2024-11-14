package dirsyn

/*
SubtreeSpecification implements the Subtree Specification construct.

From Appendix A of RFC 3672:

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

From § 6 of RFC 3642:

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
*/
type SubtreeSpecification struct {
	Base                LocalName
	SpecificExclusions  SpecificExclusions
	Min                 BaseDistance
	Max                 BaseDistance
	SpecificationFilter Refinement
}

/*
SubtreeSpecification returns an error following an analysis of x in the
context of a Subtree Specification.
*/
func (r RFC3672) SubtreeSpecification(x any) (ss SubtreeSpecification, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Subtree Specification"); err != nil {
		return
	}

	if raw[0] != '{' || raw[len(raw)-1] != '}' {
		err = errorTxt("SubtreeSpecification {} encapsulation error")
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
		if ss.SpecificExclusions, end, err = subtreeExclusions(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`specificExclusions`] = []int{begin, end}
	}

	if begin := stridx(raw, `minimum `); begin != -1 {
		var end int
		begin += 8
		if ss.Min, end, err = subtreeMinMax(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`minimum`] = []int{begin, end}
	}

	if begin := stridx(raw, `maximum `); begin != -1 {
		var end int
		begin += 8
		if ss.Max, end, err = subtreeMinMax(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`maximum`] = []int{begin, end}
	}

	if begin := stridx(raw, `specificationFilter `); begin != -1 {
		begin += 20
		if ss.SpecificationFilter, err = subtreeRefinement(raw, begin); err != nil {
			return
		}
		end := begin + len(raw) - begin
		ranges[`specificationFilter`] = []int{begin, end}
	}

	return
}

/*
Encode returns the ASN.1 encoding of the receiver instance alongside an error.
*/
func (r SubtreeSpecification) Encode() (b []byte, err error) {
	b, err = asn1m(r)
	return
}

/*
Decode returns an error following an attempt to decode ASN.1 encoded bytes b into
the receiver instance. This results in the receiver being overwritten with new data.
*/
func (r *SubtreeSpecification) Decode(b []byte) (err error) {
	var rest []byte
	if rest, err = asn1um(b, r); err == nil {
		if len(rest) > 0 {
			err = errorTxt("Extra left-over content found during ASN.1 unmarshal: '" + string(rest) + "'")
		}
	}

	return
}

/*
SpecificExclusions implements the Subtree Specification exclusions construct.

From Appendix A of RFC 3672:

	SpecificExclusions = "{" [ sp SpecificExclusion *( "," sp SpecificExclusion ) ] sp "}"
*/
type SpecificExclusions []SpecificExclusion

/*
SpecificExclusion implements the Subtree Specification exclusion construct.

From Appendix A of RFC 3672:

	SpecificExclusion  = chopBefore / chopAfter
	chopBefore         = id-chopBefore ":" LocalName
	chopAfter          = id-chopAfter  ":" LocalName
	id-chopBefore      = %x63.68.6F.70.42.65.66.6F.72.65 ; "chopBefore"
	id-chopAfter       = %x63.68.6F.70.41.66.74.65.72    ; "chopAfter"
*/
type SpecificExclusion struct {
	Name  LocalName
	After bool // false = Before
}

type BaseDistance int
type LocalName string

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

func (r SpecificExclusion) String() (s string) {
	if len(r.Name) > 0 {
		if r.After {
			s = `chopAfter ` + `"` + string(r.Name) + `"`
		} else {
			s = `chopBefore ` + `"` + string(r.Name) + `"`
		}
	}

	return
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
	excl = make(SpecificExclusions, 0)

	for i := 0; i < len(values); i += 2 {
		var ex SpecificExclusion
		if !strInSlice(values[i], []string{`chopBefore`, `chopAfter`}) {
			err = errorTxt("Unexpected key '" + values[i] + "'")
			break

		}
		ex.After = values[i] == `chopAfter`

		localName := trim(trimR(values[i+1], `,`), `"`)
		if err = isSafeUTF8(localName); err == nil {
			ex.Name = LocalName(localName)
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

func (r SubtreeSpecification) String() (s string) {
	var _s []string
	if len(r.Base) > 0 {
		_s = append(_s, `base `+`"`+string(r.Base)+`"`)
	}

	if x := r.SpecificExclusions; len(x) > 0 {
		_s = append(_s, `specificExclusions `+x.String())
	}

	if r.Min > 0 {
		_s = append(_s, `minimum `+itoa(int(r.Min)))

	}

	if r.Max > 0 {
		_s = append(_s, `maximum `+itoa(int(r.Max)))

	}

	if r.SpecificationFilter != nil {
		x := r.SpecificationFilter.String()
		_s = append(_s, `specificationFilter `+x)
	}

	s = `{` + join(_s, `, `) + `}`

	return
}

/*
Refinement implements Appendix A of RFC 3672, and serves as
the "SpecificationFilter" optionally found within a Subtree
Specification. It is qualified through instances of:

  - [ItemRefinement]
  - [AndRefinement]
  - [OrRefinement]
  - [NotRefinement]

From Appendix A of RFC 3672:

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

From § 12.3.5 of X.501:

	Refinement ::= CHOICE {
		item [0] OBJECT-CLASS.&id,
		and  [1] SET SIZE (1..MAX) OF Refinement,
		or   [2] SET SIZE (1..MAX) OF Refinement,
		not  [3] Refinement,
		... }
*/
type Refinement interface {
	IsZero() bool
	String() string
	Type() string
	Len() int
}

/*
And implements slices of [Refinement], all of which are expected to
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
	return &(r.Refinement) == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ItemRefinement) IsZero() bool {
	return &r == nil
}

/*
String returns the string representation of the receiver instance.
*/
func (r AndRefinement) String() string {
	if r.IsZero() {
		return ``
	}

	var parts []string
	for _, ref := range r {
		parts = append(parts, ref.String())
	}
	return "and:{" + join(parts, ",") + "}"
}

/*
Type returns the string literal "and".
*/
func (r AndRefinement) Type() string {
	return "and"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r AndRefinement) Len() int {
	return len(r)
}

/*
Or implements slices of [Refinement], at least one of which is
expected to evaluate as true during processing.

Instances of this type qualify the [Refinement] interface type.
*/
type OrRefinement []Refinement

/*
String returns the string representation of the receiver instance.
*/
func (r OrRefinement) String() string {
	if r.IsZero() {
		return ``
	}

	var parts []string
	for _, ref := range r {
		parts = append(parts, ref.String())
	}
	return "or:{" + join(parts, ",") + "}"
}

/*
Type returns the string literal "or".
*/
func (r OrRefinement) Type() string {
	return "or"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r OrRefinement) Len() int {
	return len(r)
}

/*
NotRefinement implements a negated, recursive instance of
[Refinement]. Normally during processing, instances
of this type are processed first when present among
other qualifiers as siblings (slices), such as with
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
Type returns the string literal "not".
*/
func (r NotRefinement) Type() string {
	return "not"
}

/*
Len returns the integer length of the receiver instance.
*/
func (r NotRefinement) Len() int {
	return r.Refinement.Len()
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
func (r ItemRefinement) String() string {
	if r.IsZero() {
		return ``
	}

	return `item:` + string(r)
}

/*
Type returns the string literal "item".
*/
func (r ItemRefinement) Type() string {
	return "item"
}

/*
Len always returns the integer 1 (one).  This
method only exists to satisfy Go's interface
signature requirements.
*/
func (r ItemRefinement) Len() int {
	return 1
}

func subtreeBase(x any) (base LocalName, end int, err error) {
	end = -1
	var raw string
	if raw, err = assertString(x, 1, "Subtree Base"); err != nil {
		return
	}

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
