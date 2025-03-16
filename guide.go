package dirsyn

/*
EnhancedGuide implements the Enhanced Guide type.

From [§ 3.3.10 of RFC 4517]:

	EnhancedGuide = object-class SHARP WSP criteria WSP
	                   SHARP WSP subset
	object-class  = WSP oid WSP
	subset        = "baseObject" / "oneLevel" / "wholeSubtree"

	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")

From [ITU-T Rec. X.520, clause 9.2.11]:

	EnhancedGuide ::= SEQUENCE {
		objectClass	[0] OBJECT-CLASS.&id,
		criteria	[1] Criteria,
		subset		[2] INTEGER {
			baseObject      (0),
			oneLevel        (1),
			wholeSubtree    (2)} DEFAULT oneLevel,
	... }

[§ 3.3.10 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10
[ITU-T Rec. X.520, clause 9.2.11]: https://www.itu.int/rec/T-REC-X.520
*/
type EnhancedGuide struct {
	ObjectClass string   `asn1:"tag:0"`
	Criteria    Criteria `asn1:"tag:1"`
	Subset      int      `asn1:"tag:2,default:1"`
}

/*
EnhancedGuide returns an instance of [EnhancedGuide] alongside an error.
*/
func (r RFC4517) EnhancedGuide(x any) (EnhancedGuide, error) {
	return marshalEnhancedGuide(x)
}

func enhancedGuide(x any) (result Boolean) {
	_, err := marshalEnhancedGuide(x)
	result.Set(err == nil)
	return
}

func marshalEnhancedGuide(x any) (g EnhancedGuide, err error) {
	var raw string
	if raw, err = assertString(x, 5, "Enhanced Guide"); err != nil {
		return
	}

	raws := splitUnescaped(raw, `#`, `\`)
	if len(raws) != 3 {
		err = errorTxt("Invalid Enhanced Guide value")
		return
	}

	// object-class is the first of three (3)
	// mandatory Enhanced Guide components.
	oc := trimS(raws[0])
	if res := oID(oc); !res.True() {
		err = errorTxt("Invalid object-class for Enhanced Guide: " + oc)
		return
	}
	g.ObjectClass = oc

	// criteria is the second of three (3)
	// mandatory Enhanced Guide components.
	cp := newCriteriaParser(raws[1])
	if g.Criteria = cp.tokenizeCriteria(); g.Criteria.IsZero() {
		err = errorTxt("Invalid Criteria for Enhanced Guide: " + raws[1])
		return
	}

	// subset is the last of three (3)
	// mandatory Enhanced Guide components.
	if g.Subset = subsetToInt(raws[2]); g.Subset == -1 {
		err = errorTxt("Incompatible subset for Enhanced Guide: " + raws[2])
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r EnhancedGuide) String() (s string) {
	if &r != nil {
		s = r.ObjectClass + `#` +
			r.Criteria.String() + `#` +
			intToSubset(r.Subset)
	}

	return
}

func subsetToInt(x string) (i int) {
	i = -1
	switch lc(trimS(x)) {
	case `baseobject`:
		i = 0
	case `onelevel`:
		i = 1
	case `wholesubtree`:
		i = 2
	}

	return
}

func intToSubset(x int) (s string) {
	s = `oneLevel`
	switch x {
	case 0:
		s = `baseObject`
	case 2:
		s = `wholeSubtree`
	}

	return
}

/*
Deprecated: Guide is OBSOLETE and is provided for historical support only;
use [EnhancedGuide] instead.

From [§ 3.3.14 of RFC 4517]:

	Guide = [ object-class SHARP ] criteria

	object-class  = WSP oid WSP
	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")

[§ 3.3.14 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.14
*/
type Guide struct {
	ObjectClass string   `asn1:"tag:0,optional"`
	Criteria    Criteria `asn1:"tag:1"`
}

/*
Guide returns an instance of [Guide] alongside an error.
*/
func (r RFC4517) Guide(x any) (Guide, error) {
	return marshalGuide(x)
}

func guide(x any) (result Boolean) {
	_, err := marshalGuide(x)
	result.Set(err == nil)
	return
}

func marshalGuide(x any) (g Guide, err error) {
	var raw string
	if raw, err = assertString(x, 5, "Guide"); err != nil {
		return
	}

	raws := splitUnescaped(raw, `#`, `\`)

	switch l := len(raws); l {
	case 1:
		// Assume single value is the criteria
		cp := newCriteriaParser(raws[0])
		g.Criteria = cp.tokenizeCriteria()
	case 2:
		// Assume two (2) components represent the
		// object-class and criteria respectively.
		oc := trimS(raws[0])
		if res := oID(oc); res.True() {
			g.ObjectClass = oc
			cp := newCriteriaParser(raws[1])
			g.Criteria = cp.tokenizeCriteria()
		}
	default:
		err = errorTxt("Unexpected component length for Guide; want 2, got " +
			fmtInt(int64(l), 10))
	}

	if err == nil {
		if g.Criteria.IsZero() {
			err = errorTxt("Invalid Criteria for Guide: " + raws[0])
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r Guide) String() (s string) {
	if &r != nil {
		if r.ObjectClass != "" {
			s += r.ObjectClass + `#`
		}
		s += r.Criteria.String()
	}

	return
}

/*
Term implements the slice component of an instance of [AndTerm].  Term
is qualified through instances of [AttributeMatchTerm], [BoolTerm],
and [Criteria].
*/
type Term interface {
	String() string
	IsZero() bool
}

/*
NotTerm negates an instance of [Term].
*/
type NotTerm struct {
	Term
}

/*
String returns the string representation of the receiver instance.
*/
func (r NotTerm) String() (s string) {
	if !r.IsZero() {
		s = "!" + r.Term.String()
	}
	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NotTerm) IsZero() bool { return r.Term == nil }

/*
TODO - correct this.

	   CriteriaItem ::= CHOICE {
		equality         [0] AttributeType,
		substrings       [1] AttributeType,
		greaterOrEqual   [2] AttributeType,
		lessOrEqual      [3] AttributeType,
		approximateMatch [4] AttributeType,
	        ... }
*/
type AttributeMatchTerm struct {
	AttributeType string
	MatchType     string
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeMatchTerm) String() string {
	return r.AttributeType + "$" + r.MatchType
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeMatchTerm) IsZero() bool { return &r == nil }

/*
BoolTerm implements a Boolean [Term] qualifier.
*/
type BoolTerm struct {
	bool
}

/*
String returns the string representation of the receiver instance.
*/
func (b BoolTerm) String() (t string) {
	t = `?false`
	if b.bool {
		t = `?true`
	}
	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BoolTerm) IsZero() bool { return &r == nil }

/*
Criteria implements the Criteria syntax per [ITU-T Rec. X.520, clause
6.5.2].

	Criteria ::= CHOICE {
	        type [0] CriteriaItem
	        and  [1] SET OF Criteria,
	        or   [2] SET OF Criteria,
	        not  [3] Criteria,
	... }

[ITU-T Rec. X.520, clause 6.5.2]: https://www.itu.int/rec/T-REC-X.520
*/
type Criteria struct {
	Set   []AndTerm
	Paren bool
}

/*
String returns the string representation of the receiver instance.
*/
func (c Criteria) String() string {
	var terms []string
	for _, term := range c.Set {
		terms = append(terms, term.String())
	}

	s := join(terms, "|")
	if c.Paren {
		s = `(` + s + `)`
	}

	return s
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r Criteria) IsZero() bool { return &r == nil }

/*
Len returns the integer length of the receiver instance.
*/
func (r Criteria) Len() int { return len(r.Set) }

/*
Index returns the Nth slice instance of [AndTerm] found within the
receiver instance.
*/
func (r Criteria) Index(idx int) (a AndTerm) {
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			a = r.Set[idx]
		}
	}

	return
}

type AndTerm struct {
	Set   []Term
	Paren bool
}

/*
Len returns the integer length of the receiver instance.
*/
func (r AndTerm) Len() int { return len(r.Set) }

/*
String returns the string representation of the receiver instance.
*/
func (a AndTerm) String() string {
	var terms []string
	for _, term := range a.Set {
		terms = append(terms, term.String())
	}

	s := join(terms, "&")
	if a.Paren {
		s = `(` + s + `)`
	}

	return s
}

/*
Index returns the Nth slice instance of [Term] found within the
receiver instance.
*/
func (r AndTerm) Index(idx int) (t Term) {
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			t = r.Set[idx]
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AndTerm) IsZero() bool { return &r == nil }

type criteriaParser struct {
	input string
	pos   int
}

func newCriteriaParser(input string) *criteriaParser {
	return &criteriaParser{input: trimS(input), pos: 0}
}

func (t *criteriaParser) next() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	ch := t.input[t.pos]
	t.pos++
	return ch
}

func (t *criteriaParser) peek() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	return t.input[t.pos]
}

func (t *criteriaParser) tokenizeCriteria() Criteria {
	var andTerms Criteria
	andTerms.Set = append(andTerms.Set, t.tokenizeAndTerm())
	for t.peek() == '|' {
		t.next()
		andTerms.Set = append(andTerms.Set, t.tokenizeAndTerm())
	}
	return andTerms
}

func (t *criteriaParser) tokenizeAndTerm() AndTerm {
	var terms AndTerm
	terms.Set = append(terms.Set, t.tokenizeTerm())
	for t.peek() == '&' {
		t.next()
		terms.Set = append(terms.Set, t.tokenizeTerm())
	}
	return terms
}

func (t *criteriaParser) tokenizeTerm() Term {
	switch t.peek() {
	case '!':
		t.next()
		return NotTerm{Term: t.tokenizeTerm()}
	case '(':
		t.next()
		criteria := t.tokenizeCriteria()
		criteria.Paren = true
		t.next() // Consume ')'
		return criteria
	case '?':
		t.next()
		if hasPfx(t.input[t.pos:], "true") {
			t.pos += 4
			return BoolTerm{bool: true}
		} else if hasPfx(t.input[t.pos:], "false") {
			t.pos += 5
			return BoolTerm{bool: false}
		}
	}

	attrType := t.tokenizeUntil('$')
	t.next() // Consume '$'
	matchType := t.tokenizeMatchType()
	return AttributeMatchTerm{
		AttributeType: attrType,
		MatchType:     matchType,
	}
}

func (t *criteriaParser) tokenizeUntil(delims ...byte) string {
	start := t.pos
	for {
		if t.pos >= len(t.input) {
			break
		}
		ch := t.input[t.pos]
		for _, d := range delims {
			if ch == d {
				return t.input[start:t.pos]
			}
		}
		t.pos++
	}
	return t.input[start:t.pos]
}

func (t *criteriaParser) tokenizeMatchType() (s string) {
	switch t.peek() {
	case 'E':
		if hasPfx(t.input[t.pos:], "EQ") {
			t.pos += 2
			s = "EQ"
		}
	case 'S':
		if hasPfx(t.input[t.pos:], "SUBSTR") {
			t.pos += 6
			s = "SUBSTR"
		}
	case 'G':
		if hasPfx(t.input[t.pos:], "GE") {
			t.pos += 2
			s = "GE"
		}
	case 'L':
		if hasPfx(t.input[t.pos:], "LE") {
			t.pos += 2
			s = "LE"
		}
	case 'A':
		if hasPfx(t.input[t.pos:], "APPROX") {
			t.pos += 6
			s = "APPROX"
		}
	}

	return
}
