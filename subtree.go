package dirsyn

import (
	"github.com/JesseCoretta/go-stackage"
)

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
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Subtree Specification", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Subtree Specification")
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
		var end int
		begin += 20
		if ss.SpecificationFilter, end, err = subtreeRefinement(raw, begin); err != nil {
			return
		}
		end = begin + end
		ranges[`specificationFilter`] = []int{begin, end}
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

type cop stackage.ComparisonOperator

const equalityOperator cop = cop(0)

func (r cop) String() string  { return `:` }
func (r cop) Context() string { return `Subtree Specification Filter Equality Operator` }

func (r SpecificExclusions) String() string {
	var _s []string
	for i := 0; i < len(r); i++ {
		_s = append(_s, r[i].String())
	}

	return join(_s, `, `)
}

func (r SpecificExclusion) String() string {
	if r.After {
		return `chopAfter ` + `"` + string(r.Name) + `"`
	}
	return `chopBefore ` + `"` + string(r.Name) + `"`
}

func newRefinement(rp *refinementParser) (r Refinement, err error) {
	if rp == nil {
		err = errorTxt("nil specFilterParser instance")
		return
	}

	r = Refinement(newStack(`refinements`, rp))

	return
}

func newStack(name string, rp *refinementParser) (s stackage.Stack) {
	var aux stackage.Auxiliary = make(stackage.Auxiliary, 0)
	aux.Set(`sfp`, rp)
	aux.Set(`pct`, 0)

	return stackage.List().
		SetID(name).
		NoPadding(true).
		SetDelimiter(',').
		SetAuxiliary(aux)
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

/*
newCondition returns a valueless instance of Condition. Everything other than
Expression has been set, and a new value may be set at any time by the user.
*/
func newCondition(name string, rp *refinementParser) (c stackage.Condition) {
	c.Init()
	c.NoPadding(true)
	c.SetKeyword(name)
	c.SetOperator(equalityOperator)
	c.SetExpression(Refinement(newStack(`refinements`, rp)))

	var aux stackage.Auxiliary = make(stackage.Auxiliary, 0)
	aux.Set(`sfp`, rp)
	c.SetAuxiliary(aux)

	return
}

func newAnd(rp *refinementParser) And {
	_and := newCondition(`and`, rp)
	_refs := _and.Expression()
	if ands, ok := _refs.(Refinement); ok {
		ands.cast().Encap([]string{`{`, `}`})
	}

	return And(_and)
}

func newOr(rp *refinementParser) Or {
	_or := newCondition(`or`, rp)
	_refs := _or.Expression()
	if ors, ok := _refs.(Refinement); ok {
		ors.cast().Encap([]string{`{`, `}`})
	}

	return Or(_or)
}

func newNot(rp *refinementParser) Not {
	_not := newCondition(`not`, rp)
	_refs := _not.Expression()
	if nots, ok := _refs.(Refinement); ok {
		nots.cast().Encap([]string{`{`, `}`})
	}

	return Not(_not)
}

func (r Refinement) cast() stackage.Stack {
	return stackage.Stack(r)
}

func (r SubtreeSpecification) String() (s string) {
	var _s []string
	if len(r.Base) > 0 {
		_s = append(_s, `base `+`"`+string(r.Base)+`"`)
	}

	if x := r.SpecificExclusions.String(); len(x) > 0 {
		_s = append(_s, `specificExclusions `+x)
	}

	if r.Min > 0 {
		_s = append(_s, `minimum `+itoa(int(r.Min)))

	}

	if r.Max > 0 {
		_s = append(_s, `maximum `+itoa(int(r.Max)))

	}

	if x := r.SpecificationFilter.String(); len(x) > 0 {
		_s = append(_s, `specificationFilter `+x)
	}

	s = `{ ` + join(_s, `, `) + ` }`

	return
}

func (r And) String() string {
	_refs := r.cast().Expression()
	ands, _ := _refs.(Refinement)

	return r.cast().Keyword() + `:` + `{` + ands.String() + `}`
}

func (r Item) String() string {
	return `item:` + string(r)
}

func (r Or) String() string {
	_refs := r.cast().Expression()
	ors, _ := _refs.(Refinement)

	return r.cast().Keyword() + `:` + `{` + ors.String() + `}`
}

func (r Not) String() string {
	_refs := r.cast().Expression()
	not, _ := _refs.(Refinement)

	return r.cast().Keyword() + `:` + not.String()
}

func (r Refinement) String() string {
	var str []string
	s := r.cast()

	for i := 0; i < s.Len(); i++ {
		slice, _ := s.Index(i)
		switch tv := slice.(type) {
		case Item:
			str = append(str, tv.String())
		case Refinement:
			str = append(str, tv.String())
		case And:
			str = append(str, tv.String())
		case Or:
			str = append(str, tv.String())
		case Not:
			str = append(str, tv.String())
		}
	}

	return join(str, `,`)
}

func (r And) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r Or) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r Not) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r Refinement) rp() (rp *refinementParser) {
	x := r.cast().Auxiliary()
	_rp, _ := x.Get(`sfp`)
	rp = _rp.(*refinementParser)

	return
}

func (r Refinement) pct() int {
	x := r.cast().Auxiliary()
	_rp, _ := x.Get(`pct`)
	return _rp.(int)
}

func (r Refinement) incrPct() {
	x := r.cast().Auxiliary()
	_pct, _ := x.Get(`pct`)
	pct := _pct.(int) + 1
	x.Set(`pct`, pct)
}

func (r Refinement) decrPct() {
	x := r.cast().Auxiliary()
	_pct, _ := x.Get(`pct`)
	pct := _pct.(int) - 1
	x.Set(`pct`, pct)
}

func (r Refinement) push(refs any) {
	switch tv := refs.(type) {
	case Refinement:
		r.cast().Push(tv)
	case And, Or, Item:
		r.cast().Push(tv)
	}
}

func (r And) push(refs any) {
	_refs := r.cast().Expression()
	ands, _ := _refs.(Refinement)

	switch tv := refs.(type) {
	case Refinement:
		ands.cast().Push(tv)
	case And, Or, Item:
		ands.cast().Push(tv)
	}
}

func (r Or) push(refs any) {
	_refs := r.cast().Expression()
	ors, _ := _refs.(Refinement)

	switch tv := refs.(type) {
	case Refinement:
		ors.cast().Push(tv)
	case And, Or, Not, Item:
		ors.cast().Push(tv)
	}
}

func (r Not) push(refs any) {
	_refs := r.cast().Expression()
	nots, _ := _refs.(Refinement)

	switch tv := refs.(type) {
	case Refinement:
		nots.cast().Push(tv)
	case And, Or, Not, Item:
		nots.cast().Push(tv)
	}
}

/*
Refinement implements the Subtree Specification Refinement construct.

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
*/
type Refinement stackage.Stack

/*
Refinement ::= CHOICE {
item [0] OBJECT-CLASS.&id,
and  [1] SET SIZE (1..MAX) OF Refinement,
or   [2] SET SIZE (1..MAX) OF Refinement,
not  [3] Refinement,
... }
*/

type Item string
type And stackage.Condition
type Not stackage.Condition
type Or stackage.Condition

type refinementParser struct {
	input string
	pos   int
}

func subtreeBase(x any) (base LocalName, end int, err error) {
	end = -1
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Subtree Base", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Subtree Base")
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

func subtreeRefinement(x any, begin int) (refs Refinement, end int, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Specification Filter", 0)
			return
		}
		raw = tv[begin:]
	default:
		err = errorBadType("Specification Filter")
		return
	}

	var rp *refinementParser
	if rp, _, end, err = newRefinementParser(raw); err != nil {
		return
	}

	if refs, err = newRefinement(rp); err != nil {
		return
	}

	if !refs.refinement() {
		err = errorTxt("Refinement failed")
		return
	}
	refs.cast().Reveal() // in case of any needlessly enveloped stacks ...

	return
}

func newRefinementParser(x string) (r *refinementParser, start, end int, err error) {
	end = -1
	r = new(refinementParser)

	ctl, ctr := strcnt(x, `{`), strcnt(x, `}`)
	if ctl != ctr {
		err = errorTxt("Malformed brace ({}) encapsulation for specificationFilter refinement statement")
		return
	}

	end = len(x)
	r.input = trimS(x[:])

	return
}

func (r Refinement) and() bool {
	sfp := r.rp()

	if hasPfx(sfp.input[sfp.pos:], `and:`) {
		sfp.pos += 4
		ref := newAnd(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinement) or() bool {
	sfp := r.rp()

	if hasPfx(sfp.input[sfp.pos:], `or:`) {
		sfp.pos += 3
		ref := newOr(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinement) not() bool {
	sfp := r.rp()

	if hasPfx(sfp.input[sfp.pos:], `not:`) {
		sfp.pos += 4
		ref := newNot(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinement) item() bool {
	sfp := r.rp()
	sfp.pos += 5

	// If we only received a single item, try to
	// handle it now.
	var s RFC4512
	if err := s.OID(sfp.input[sfp.pos:]); err == nil {
		r.push(Item(sfp.input[sfp.pos:]))
		return true
	}

	for idx, ch := range sfp.input[sfp.pos:] {
		if ch == '-' || ch == '.' || isAlphaNumeric(rune(ch)) {
			continue
		}

		if err := s.OID(sfp.input[sfp.pos : sfp.pos+idx]); err != nil {
			return false
		}

		r.push(Item(sfp.input[sfp.pos : sfp.pos+idx]))

		sfp.pos += idx

		break
	}

	return r.refinement()
}

func (r And) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinement)
	return refs.refinement()
}

func (r Or) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinement)
	return refs.refinement()
}

func (r Not) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinement)
	return refs.refinement()
}

func (r Refinement) refinement() bool {
	sfp := r.rp()

	switch {
	case sfp.input[sfp.pos] == ',':
		sfp.pos++
		return r.refinement()
	case hasPfx(sfp.input[sfp.pos:], "{"):
		r.incrPct()

		sfp.pos++
		if !(r.refinement() || hasPfx(sfp.input[sfp.pos:], "}")) {
			return false
		}
		sfp.pos++
		return true
	case hasPfx(sfp.input[sfp.pos:], ` `):
		sfp.pos++
		return r.refinement()
	case hasPfx(sfp.input[sfp.pos:], `item:`):
		return r.item()
	case hasPfx(sfp.input[sfp.pos:], `and:`):
		return r.and()
	case hasPfx(sfp.input[sfp.pos:], `not:`):
		return r.not()
	case hasPfx(sfp.input[sfp.pos:], `or:`):
		return r.or()
	}

	return false
}
