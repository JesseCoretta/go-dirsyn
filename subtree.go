package dirsyn

import "github.com/JesseCoretta/go-stackage"

/*
SubtreeSpecification returns an error following an analysis of x in the
context of a Subtree Specification.

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

	id-base                = %x62.61.73.65 ; "base"
	id-specificExclusions  = %x73.70.65.63.69.66.69.63.45.78.63.6C.75.73.69.6F.6E.73 ; "specificExclusions"
	id-minimum             = %x6D.69.6E.69.6D.75.6D ; "minimum"
	id-maximum             = %x6D.61.78.69.6D.75.6D ; "maximum"
	id-specificationFilter = %x73.70.65.63.69.66.69.63.61.74.69.6F.6E.46.69.6C.74.65.72 ; "specificationFilter"

	SpecificExclusions = "{" [ sp SpecificExclusion *( "," sp SpecificExclusion ) ] sp "}"
	SpecificExclusion  = chopBefore / chopAfter
	chopBefore         = id-chopBefore ":" LocalName
	chopAfter          = id-chopAfter  ":" LocalName
	id-chopBefore      = %x63.68.6F.70.42.65.66.6F.72.65 ; "chopBefore"
	id-chopAfter       = %x63.68.6F.70.41.66.74.65.72    ; "chopAfter"

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

	ss.SpecificationFilter, err = subtreeSpecificationFilter(raw)

	return
}

type SubtreeSpecification struct {
	Base string
	Min,
	Max int
	SpecificationFilter SpecificationFilter
}

type cop stackage.ComparisonOperator

const equalityOperator cop = cop(0)

func (r cop) String() string  { return `:` }
func (r cop) Context() string { return `Subtree Specification Filter Equality Operator` }

/*
SpecificationFilter is a type alias of the [stackage.Condition] type.
Instances of this type circumscribe the following construct:

	"specificationFilter"           ":"              { ... }
	      keyword           comparison operator    Refinements

Instances of this type are used as the top-level component in the
parsing operation.
*/
type SpecificationFilter stackage.Condition

func (r SpecificationFilter) Refinements() Refinements {
	_ex := r.cast().Expression()
	ex, _ := _ex.(Refinements)
	return ex
}

func newSpecificationFilter(sfp *specificationFilterParser) (r SpecificationFilter, err error) {
	if sfp == nil {
		err = errorTxt("nil specFilterParser instance")
		return
	}

	var c stackage.Condition = newCondition(`specificationFilter`, sfp)
	c.SetExpression(Refinements(newStack(`refinements`, sfp)))
	r = SpecificationFilter(c)

	return

}

func newStack(name string, sfp *specificationFilterParser) (s stackage.Stack) {
	var aux stackage.Auxiliary = make(stackage.Auxiliary, 0)
	aux.Set(`sfp`, sfp)
	aux.Set(`pct`, 0)

	return stackage.List().
		SetID(name).
		NoPadding(true).
		SetDelimiter(',').
		SetAuxiliary(aux)
}

/*
newCondition returns a valueless instance of Condition. Everything other than
Expression has been set, and a new value may be set at any time by the user.
*/
func newCondition(name string, sfp *specificationFilterParser) (c stackage.Condition) {
	c.Init()
	c.NoPadding(true)
	c.SetKeyword(name)
	c.SetOperator(equalityOperator)
	c.SetExpression(Refinements(newStack(`refinements`, sfp)))

	var aux stackage.Auxiliary = make(stackage.Auxiliary, 0)
	aux.Set(`sfp`, sfp)
	c.SetAuxiliary(aux)

	return
}

func newAnd(sfp *specificationFilterParser) AndRefinement {
	_and := newCondition(`and`, sfp)
	_refs := _and.Expression()
	if ands, ok := _refs.(Refinements); ok {
		ands.cast().Encap([]string{`{`, `}`})
	}

	return AndRefinement(_and)
}

func newOr(sfp *specificationFilterParser) OrRefinement {
	_or := newCondition(`or`, sfp)
	_refs := _or.Expression()
	if ors, ok := _refs.(Refinements); ok {
		ors.cast().Encap([]string{`{`, `}`})
	}

	return OrRefinement(_or)
}

func newNot(sfp *specificationFilterParser) NotRefinement {
	_not := newCondition(`not`, sfp)
	_refs := _not.Expression()
	if nots, ok := _refs.(Refinements); ok {
		nots.cast().Encap([]string{`{`, `}`})
	}

	return NotRefinement(_not)
}

func (r SpecificationFilter) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r Refinements) cast() stackage.Stack {
	return stackage.Stack(r)
}

func (r Refinement) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r AndRefinement) String() string {
	_refs := r.cast().Expression()
	ands, _ := _refs.(Refinements)

	return r.cast().Keyword() + `:` + `{` + ands.String() + `}`
}

func (r OrRefinement) String() string {
	_refs := r.cast().Expression()
	ors, _ := _refs.(Refinements)

	return r.cast().Keyword() + `:` + `{` + ors.String() + `}`
}

func (r NotRefinement) String() string {
	_refs := r.cast().Expression()
	not, _ := _refs.(Refinements)

	return r.cast().Keyword() + `:` + not.String()
}

func (r Refinement) String() (str string) {
	_refs := r.cast().Expression()
	switch tv := _refs.(type) {
	case string:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv
	case Refinement:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv.String()
	case Refinements:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv.String()
	case AndRefinement:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv.String()
	case OrRefinement:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv.String()
	case NotRefinement:
		str = r.cast().Keyword() + r.cast().Operator().String() + tv.String()
	}

	return
}

func (r Refinements) String() string {
	var str []string
	s := r.cast()

	for i := 0; i < s.Len(); i++ {
		slice, _ := s.Index(i)
		switch tv := slice.(type) {
		case Refinement:
			str = append(str, tv.String())
		case Refinements:
			str = append(str, tv.String())
		case AndRefinement:
			str = append(str, tv.String())
		case OrRefinement:
			str = append(str, tv.String())
		case NotRefinement:
			str = append(str, tv.String())
		}
	}

	return join(str, `,`)
}

func (r SpecificationFilter) String() string {
	casted := r.cast()
	ex := casted.Expression().(Refinements)
	return casted.Keyword() + string(rune(32)) + ex.String()
}

func (r AndRefinement) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r OrRefinement) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r NotRefinement) cast() stackage.Condition {
	return stackage.Condition(r)
}

func (r SpecificationFilter) sfp() (sfp *specificationFilterParser) {
	x := r.cast().Auxiliary()
	_sfp, _ := x.Get(`sfp`)
	sfp = _sfp.(*specificationFilterParser)

	return
}

func (r Refinements) sfp() (sfp *specificationFilterParser) {
	x := r.cast().Auxiliary()
	_sfp, _ := x.Get(`sfp`)
	sfp = _sfp.(*specificationFilterParser)

	return
}

func (r Refinements) pct() int {
	x := r.cast().Auxiliary()
	_sfp, _ := x.Get(`pct`)
	return _sfp.(int)
}

func (r Refinements) incrPct() {
	x := r.cast().Auxiliary()
	_pct, _ := x.Get(`pct`)
	pct := _pct.(int) + 1
	x.Set(`pct`, pct)
}

func (r Refinements) decrPct() {
	x := r.cast().Auxiliary()
	_pct, _ := x.Get(`pct`)
	pct := _pct.(int) - 1
	x.Set(`pct`, pct)
}

func (r SpecificationFilter) push(refs any) {
	_ref := r.cast().Expression()
	if _refs, ok := _ref.(Refinements); ok {
		_refs.push(refs)
	}
}

func (r Refinements) push(refs any) {
	switch tv := refs.(type) {
	case Refinements:
		r.cast().Push(tv)
	case Refinement, AndRefinement, OrRefinement:
		r.cast().Push(tv)
	}
}

func (r AndRefinement) push(refs any) {
	_refs := r.cast().Expression()
	ands, _ := _refs.(Refinements)

	switch tv := refs.(type) {
	case Refinements:
		ands.cast().Push(tv)
	case Refinement, AndRefinement, OrRefinement:
		ands.cast().Push(tv)
	}
}

func (r OrRefinement) push(refs any) {
	_refs := r.cast().Expression()
	ors, _ := _refs.(Refinements)

	switch tv := refs.(type) {
	case Refinements:
		ors.cast().Push(tv)
	case Refinement, AndRefinement, OrRefinement, NotRefinement:
		ors.cast().Push(tv)
	}
}

func (r NotRefinement) push(refs any) {
	_refs := r.cast().Expression()
	nots, _ := _refs.(Refinements)

	switch tv := refs.(type) {
	case Refinements:
		nots.cast().Push(tv)
	case Refinement, AndRefinement, OrRefinement, NotRefinement:
		nots.cast().Push(tv)
	}
}

/*
Refinements is a type alias of the [stackage.Stack] type. Instances of
this type circumscribe a specificationFilter statement in the form of
nested [stackage.Stack] instances which, ultimately, contain a core
[Refinement] instance.
*/
type Refinements stackage.Stack

/*
Refinement is a type alias of the [stakage.Condition] type.  Instances of
this type represent the core "atom" or component of the specificationFilter
value, typically in the form of a specificationFilter "item", or a negation
of same.  A value may also be an instance of [AndRefinement], [NotRefinement]
and [OrRefinement]
*/
type Refinement stackage.Condition
type AndRefinement stackage.Condition
type NotRefinement stackage.Condition
type OrRefinement stackage.Condition

type specificationFilterParser struct {
	input string
	pos   int
}

func subtreeSpecificationFilter(x any) (ssf SpecificationFilter, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Specification Filter", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Specification Filter")
		return
	}

	var sfp *specificationFilterParser
	//var start, end int
	if sfp, _, _, err = newSpecificationFilterParser(raw); err != nil {
		return
	}

	if ssf, err = newSpecificationFilter(sfp); err != nil {
		return
	}

	if !ssf.Refinements().refinement() {
		err = errorTxt("Refinement failed")
		return
	}
	ssf.Refinements().cast().Reveal() // in case of any needlessly enveloped stacks ...

	//fmt.Printf("%s\n", ssf)

	/*
		refs := ssf.Refinements()
		slice, _ := refs.cast().Index(0)
		casted := slice.(AndRefinement).cast()
		subslice1, _ := casted.Expression().(Refinements).cast().Index(0)
		subslice2, _ := casted.Expression().(Refinements).cast().Index(1)
		subslice2a, _ := subslice2.(OrRefinement).cast().Expression().(Refinements).cast().Index(0)
		subslice2b, _ := subslice2.(OrRefinement).cast().Expression().(Refinements).cast().Index(1)
		fmt.Printf("AndRefs:%s/%s/%s/%s\n", subslice1,subslice2,subslice2a.(Refinement),subslice2b.(Refinement))
	*/

	return
}

func newSpecificationFilterParser(x string) (r *specificationFilterParser, start, end int, err error) {
	label := `specificationFilter`

	start = -1
	end = -1

	idx := stridx(x, label)
	if idx == -1 {
		// specFilter is optional, no errors plz.
		return
	}

	r = new(specificationFilterParser)
	z := x[idx+20:]

	ctl, ctr := strcnt(z, `{`), strcnt(z, `}`)
	if ctl != ctr-1 || z[len(z)-1] != '}' {
		err = errorTxt("Malformed brace ({}) encapsulation for specificationFilter refinement statement")
		return
	}

	start = idx
	end = len(x) - 1
	r.input = trimS(z[:len(z)-1])

	return
}

func (r Refinements) and() bool {
	sfp := r.sfp()

	if hasPfx(sfp.input[sfp.pos:], `and:`) {
		sfp.pos += 4
		ref := newAnd(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinements) or() bool {
	sfp := r.sfp()

	if hasPfx(sfp.input[sfp.pos:], `or:`) {
		sfp.pos += 3
		ref := newOr(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinements) not() bool {
	sfp := r.sfp()

	if hasPfx(sfp.input[sfp.pos:], `not:`) {
		sfp.pos += 4
		ref := newNot(sfp)
		r.push(ref)
		return ref.refinement()
	}

	return false
}

func (r Refinements) item() bool {
	sfp := r.sfp()
	sfp.pos += 5

	// If we only received a single item, try to
	// handle it now.
	var s RFC4512
	if err := s.OID(sfp.input[sfp.pos:]); err == nil {
		c := newCondition(`item`, sfp)
		c.SetExpression(sfp.input[sfp.pos:])
		r.push(Refinement(c))
		return true
	}

	for idx, ch := range sfp.input[sfp.pos:] {
		if ch == '-' || ch == '.' || isAlphaNumeric(rune(ch)) {
			continue
		}

		if err := s.OID(sfp.input[sfp.pos : sfp.pos+idx]); err != nil {
			return false
		}

		c := newCondition(`item`, sfp)
		c.SetExpression(sfp.input[sfp.pos : sfp.pos+idx])
		r.push(Refinement(c))

		sfp.pos += idx

		break
	}

	return r.refinement()
}

func (r AndRefinement) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinements)
	return refs.refinement()
}

func (r OrRefinement) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinements)
	return refs.refinement()
}

func (r NotRefinement) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinements)
	return refs.refinement()
}

func (r Refinement) refinement() bool {
	_refs := r.cast().Expression()
	refs, _ := _refs.(Refinements)
	return refs.refinement()
}

func (r Refinements) refinement() bool {
	sfp := r.sfp()

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
