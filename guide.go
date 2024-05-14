package dirsyn

/*
EnhancedGuide implements the Enhanced Guide syntax per ITU-T Rec. X.520.

	EnhancedGuide ::= SEQUENCE {
		objectClass	[0] OBJECT-CLASS.&id,
		criteria	[1] Criteria,
		subset		[2] INTEGER {
			baseObject	(0),
			oneLevel	(1),
			wholeSubtree	(2)} DEFAULT oneLevel,
	... }
*/
type EnhancedGuide struct {
	ObjectClass string   `asn1:"tag:0"`
	Criteria    Criteria `asn1:"tag:1"`
	Subset      int      `asn1:"tag:2,default:1"`
}

/*
EnhancedGuide implements the Criteria syntax per ITU-T Rec. X.520.

	Criteria ::= CHOICE {
		type [0] CriteriaItem
		and  [1] SET OF Criteria,
		or   [2] SET OF Criteria,
		not  [3] Criteria,
	... }

	CriteriaItem ::= CHOICE {
		equality         [0] AttributeType,
		substrings       [1] AttributeType,
		greaterOrEqual   [2] AttributeType,
		lessOrEqual      [3] AttributeType,
		approximateMatch [4] AttributeType,
	... }
*/
type Criteria struct{}

/*
EnhancedGuide returns an error following an analysis of x in the context
of an Enhanced Guide.

From § 3.3.10 of RFC 4517:

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
*/
func (r RFC4517) EnhancedGuide(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength(`Enhanced Guide`, 0)
			return
		}
		raw = tv
	default:
		err = errorBadType(`Enhanced Guide`)
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
	if err = r.OID(oc); err != nil {
		err = errorTxt("Invalid object-class for Enhanced Guide: " + oc)
		return
	}

	// criteria is the second of three (3)
	// mandatory Enhanced Guide components.
	crit := trimS(raws[1])
	if err = guideCriteria(crit); err != nil {
		return
	}

	// subset is the last of three (3)
	// mandatory Enhanced Guide components.
	subs := trimS(raws[2])
	if !strInSlice(subs, []string{
		`baseObject`,
		`oneLevel`,
		`wholeSubtree`,
	}) {
		err = errorTxt("Incompatible subset for Enhanced Guide: " + subs)
	}

	return
}

/*
Deprecated: Guide is OBSOLETE and is provided for historical support only;
use [EnhancedGuide] instead.

Guide returns an error following an analysis of x in the context of a Guide.

From § 3.3.14 of RFC 4517:

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
*/
func (r RFC4517) Guide(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Guide value", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Guide")
		return
	}

	raws := splitUnescaped(raw, `#`, `\`)
	switch l := len(raws); l {
	case 0:
		err = errorBadLength("Guide", 0)
	case 1:
		// Assume single value is the criteria
		err = guideCriteria(raws[0])
	case 2:
		// Assume two (2) components represent the
		// object-class and criteria respectively.
		oc := trimS(raws[0])
		if err = r.OID(oc); err != nil {
			err = errorTxt("Invalid object-class for Guide: " + oc)
			break
		}
		err = guideCriteria(raws[1])
	default:
		err = errorTxt("Unexpected component length for Guide; want 2, got " +
			fmtInt(int64(l), 10))
	}

	return
}

type criteriaParser struct {
	input string
	pos   int
}

func guideCriteria(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("criteria", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType(`criteria`)
		return
	}

	if r := newCriteriaParser(raw); !r.parse() {
		err = errorTxt("Invalid criteria " + r.input[r.pos:])
	}

	return
}

func newCriteriaParser(input string) *criteriaParser {
	return &criteriaParser{input: input}
}

func (p *criteriaParser) parse() bool {
	return p.criteria() && p.pos == len(p.input)
}

func (p *criteriaParser) criteria() bool {
	if !p.andTerm() {
		return false
	}
	for hasPfx(p.input[p.pos:], "|") {
		p.pos++
		if !p.andTerm() {
			return false
		}
	}
	return true
}

func (p *criteriaParser) andTerm() bool {
	if !p.term() {
		return false
	}
	for hasPfx(p.input[p.pos:], "&") {
		p.pos++
		return p.term()
	}
	return true
}

func (p criteriaParser) isPrevious(r rune) bool {
	if p.pos > 0 {
		return rune(p.input[p.pos-1]) == r
	}

	return false
}

func (p criteriaParser) isValidAmp() bool {
	if p.pos > 0 {
		return p.input[p.pos] == '&' && !p.isPrevious('&')
	}

	return false
}

func (p criteriaParser) isValidDollar() bool {
	if p.pos > 0 {
		return p.input[p.pos] == '$' && !p.isPrevious('$')
	}

	return false
}

func (p criteriaParser) isValidBoolean() (is bool) {
	switch {
	case hasPfx(p.input[p.pos:], "?true"):
		is = true
	case hasPfx(p.input[p.pos:], "?false"):
		is = true
	default:
		return
	}

	if p.pos-6 > 0 {
		if p.input[p.pos-6:p.pos] == `?false` {
			is = false
		} else if p.input[p.pos-5:p.pos] == `?true` {
			is = false
		}
	} else if p.pos-5 > 0 {
		if p.input[p.pos-5:p.pos] == `?true` {
			is = false
		}
	}

	return
}

func (p *criteriaParser) term() bool {
	switch {
	case p.isValidDollar():
		p.pos++
		return p.term()
	case p.isValidAmp():
		p.pos++
		return p.andTerm()
	case hasPfx(p.input[p.pos:], "!") && !p.isPrevious('!'):
		p.pos++
		return p.term()
	case hasPfx(p.input[p.pos:], "("):
		p.pos++
		if !(p.criteria() || hasPfx(p.input[p.pos:], ")")) {
			return false
		}
		p.pos++
		return true
	case p.isValidBoolean():
		if hasPfx(p.input[p.pos:], "?true") {
			p.pos += 5
			return true
		}
		p.pos += 6
		return true
	case isAlphaNumeric(rune(p.input[p.pos])):
		if p.isAttrMatch() {
			return p.term()
		}
	}

	return false
}

func (r *criteriaParser) isAttrMatch() (is bool) {
	var attr string
	for _, ch := range r.input[r.pos:] {
		if isDigit(ch) || ch == '.' {
			attr += string(ch)
		} else if isAlpha(ch) || ch == '-' {
			attr += string(ch)
		} else {
			break
		}
	}

	if r.input[r.pos+len(attr)] != '$' {
		return
	}

	var s RFC4512
	if err := s.OID(attr); err != nil {
		return
	}

	ismt, idx := isMatchType(r.input[r.pos+len(attr)+1:])
	if !ismt {
		return
	}

	r.pos += len(attr) + idx + 1
	is = true

	return
}

func isMatchType(x string) (is bool, idx int) {
	for _, mt := range []string{
		`EQ`,
		`GE`,
		`LE`,
		`APPROX`,
		`SUBSTR`,
	} {
		if is = hasPfx(x, mt); is {
			idx = len(mt)
			break
		}
	}

	return
}
