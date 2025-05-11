package dirsyn

/*
aci.go implements types and methods pertaining to the Netscape
Access Control Instruction Version 3.0 (ACIv3) syntax.

Note that this is largely a streamlined port of JesseCoretta/go-aci.
*/

import (
	"time"

	"github.com/JesseCoretta/go-shifty"
)

/*
ACIv3Instruction is the high-level composite type for Netscape's ACIv3
instruction construct.

Field T contains an [ACIv3TargetRule], which is always optional.

Field A contains a string intended for a helpful "label" which differentiates the
statement from other instructions -- a requirement of most directory implementations
which honor the ACIv3 syntax. This is known as an "ACL", or "Access Control Label".

Field PB contains an instance of [ACIv3PermissionBindRule], which MUST contain at
least one (1) [ACIv3PermissionBindRuleItem].
*/
type ACIv3Instruction struct {
	T  ACIv3TargetRule         // *0 ACIv3TargetRuleItem
	A  string                  //  1 ACL
	PB ACIv3PermissionBindRule // *1 ACIv3PermissionBindRuleItem
}

/*
Instruction returns an instance of [ACIv3Instruction] alongside an error following an attempt
to parse or marshal x.
*/
func (r NetscapeACIv3) Instruction(x ...any) (ACIv3Instruction, error) {
	var (
		i ACIv3Instruction = ACIv3Instruction{
			T:  ACIv3TargetRule{&aCITargetRule{}},
			PB: badACIv3PBR,
		}
		err error
	)

	switch len(x) {
	case 0:
	case 1:
		if str, ok := x[0].(string); ok {
			err = i.parse(str)
		} else {
			err = badACIv3InstructionErr
		}
	case 2:
		err = i.parseLen2(x[0], x[1])
	case 3:
		err = i.parseLen3(x[0], x[1], x[2])
	default:
		err = badACIv3InstructionErr
	}

	return i, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3Instruction) String() string {
	return r.T.String() + "(version 3.0; acl \"" +
		r.A + "\"; " + r.PB.String() + ")"
}

func (r *ACIv3Instruction) parse(x string) (err error) {
	x = trimS(x)

	tidx := stridx(x, "version 3.0;")
	if tidx == -1 || tidx == 0 {
		err = badACIv3InstructionErr
		return
	}

	if t := trimR(trimS(x[:tidx-1]), `(`); len(t) > 0 {
		err = r.T.parse(t)
	}

	if err == nil {
		n := trimS(x[tidx+12:])
		if aidx := idxr(n, '"'); aidx == -1 {
			err = badACIv3InstructionErr
		} else {
			// Read the quoted ACL string (excluding
			// quotes that are not escaped).
			a := n[aidx+1:]
			e := 0
			for i := 0; i < len(a); i++ {
				if a[i] == '"' && a[i-1] != '\\' {
					e = i + 1
					break
				}
				r.A += string(a[i])
			}

			if pb := trimS(a[e:]); len(pb) < 18 {
				err = badACIv3PBRErr
			} else if pb[0] != ';' || pb[len(pb)-1] != ')' {
				err = badACIv3InstructionErr
			} else {
				err = r.PB.parse(trimS(pb[1 : len(pb)-1]))
			}
		}
	}

	return
}

func (r *ACIv3Instruction) parseLen2(a, b any) (err error) {
	var ok bool
	if r.A, ok = a.(string); !ok || len(r.A) == 0 {
		err = badACIv3InstructionErr
	} else {
		switch tv := b.(type) {
		case string:
			err = r.PB.parse(tv)
		case ACIv3PermissionBindRule:
			if err = tv.Valid(); err == nil {
				r.PB = tv
			}
		default:
			err = badACIv3InstructionErr
		}
	}

	return
}

func (r *ACIv3Instruction) parseLen3(a, b, c any) (err error) {
	switch tv := a.(type) {
	case string:
		err = r.T.parse(tv)
	case ACIv3TargetRule:
		if err = tv.Valid(); err == nil {
			r.T = tv
		}
	default:
		err = badACIv3InstructionErr
	}

	if err == nil {
		var ok bool
		if r.A, ok = b.(string); !ok || len(r.A) == 0 {
			err = badACIv3InstructionErr
		} else {
			switch tv := c.(type) {
			case string:
				err = r.PB.parse(tv)
			case ACIv3PermissionBindRule:
				if err = tv.Valid(); err == nil {
					r.PB = tv
				}
			default:
				err = badACIv3InstructionErr
			}
		}
	}

	return
}

/*
ACIv3Keyword describes the effective "type" within the context of a given [ACIv3BindRule] or [ACIv3TargetRuleItem].

The available ACIv3Keyword instances vary based on the rule type in which a given ACIv3Keyword resides.

See the ACIv3Keyword constants defined in this package for a complete list.
*/
type ACIv3Keyword interface {
	String() string
	Kind() string

	isACIv3Keyword()
}

/*
ACIv3Operator implements a simple comparison operator
for [ACIv3BindRule] and [ACIv3TargetRuleItem] statements.
*/
type ACIv3Operator uint8

// private keyword maps exist only to keep cyclomatics down.
var (
	aCIBTMap                    map[ACIv3BindType]string
	aCIOperatorMap              map[string]ACIv3Operator
	aCIBindKeywordMap           map[ACIv3Keyword]string
	aCITargetKeywordMap         map[ACIv3Keyword]string
	aCIPermittedTargetOperators map[ACIv3Keyword][]ACIv3Operator
	aCIPermittedBindOperators   map[ACIv3Keyword][]ACIv3Operator
	aCILevelMap                 map[int]ACIv3InheritanceLevel    = make(map[int]ACIv3InheritanceLevel, 0)
	aCILevelNumbers             map[string]ACIv3InheritanceLevel = make(map[string]ACIv3InheritanceLevel, 0)
	aCIRightsMap                map[ACIv3Right]string
	aCIRightsNames              map[string]ACIv3Right
)

var (
	badACIv3Attribute      ACIv3Attribute
	badAttributeValue      AttributeValue
	badACIv3BindRule       ACIv3BindRule
	badACIv3BindKeyword    ACIv3BindKeyword
	badACIv3TargetKeyword  ACIv3TargetKeyword
	badACIv3Inheritance    ACIv3Inheritance
	badACIv3TargetRule     ACIv3TargetRule
	badACIv3TargetRuleItem ACIv3TargetRuleItem
	badACIv3Permission     ACIv3Permission
	badACIv3AM             ACIv3AuthenticationMethod
	badACIv3OID            ACIv3ObjectIdentifier
	badACIv3PBR            ACIv3PermissionBindRule
	badACIv3PBRItem        ACIv3PermissionBindRuleItem
	badACIv3Scope          ACIv3Scope
	badACIv3FQDN           ACIv3FQDN
	badACIv3IPAddress      ACIv3IPAddress
)

// ACILevel bit constraint - we don't use all of uint16 for
// ACI inheritance level bit shifting, thus there is little
// sense in iterating the whole thing.
var aCILevelBitIter int = bitSize(uint16(0)) - 4

/*
ACIv3AttributeTypeDescription contains the string representation of the Netscape
ACIv3 "aci" attribute type schema definition, formatted in the standard RFC 4512
Attribute Type Description syntax.

Directory systems which implement and honor the Netscape ACIv3 syntax for access
control purposes SHOULD register and advertise this type in the directory schema.

Facts

  - OID: 2.16.840.1.113730.3.1.55
  - Directory String SYNTAX
  - NO matching rules of any kind
  - directoryOperation USAGE
*/
const ACIv3AttributeTypeDescription = `( 2.16.840.1.113730.3.1.55 NAME 'aci' DESC 'Netscape defined access control information attribute type' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE directoryOperation X-ORIGIN 'Netscape/Sun Java Directory Servers' )`

/*
[ACIv3Right] constants are discrete left-shifted privilege aggregates that can be used in an additive (or
subtractive) manner to form a complete [ACIv3Permission] statement.
*/
const (
	ACIv3ReadAccess      ACIv3Right = 1 << iota // 1
	ACIv3WriteAccess                            // 2
	ACIv3AddAccess                              // 4
	ACIv3DeleteAccess                           // 8
	ACIv3SearchAccess                           // 16
	ACIv3CompareAccess                          // 32
	ACIv3SelfWriteAccess                        // 64
	ACIv3ProxyAccess                            // 128
	ACIv3ImportAccess                           // 256
	ACIv3ExportAccess                           // 512

	ACIv3NoAccess  ACIv3Right = 0
	ACIv3AllAccess ACIv3Right = 895 // DOES NOT INCLUDE "proxy"
)

/*
ACIv3ScopeSubordinate represents a non-standard [ACIv3Scope] value, `subordinate`, which is used
in ACIv3 types only
*/
const ACIv3ScopeSubordinate ACIv3Scope = 4

// We use token type constants with a "T" prefix so that they don’t conflict

/*
ACIv3BindType keyword constants are used in value matching definitions that utilizes either the [ACIv3BindUAT] (userattr) or [ACIv3BindGAT] (groupattr) [ACIv3BindKeyword] constant within an [ACIv3BindRule] instance.
*/
const (
	invalidACIv3BindType ACIv3BindType = iota // <invalid_bind_type>
	ACIv3BindTypeUSERDN
	ACIv3BindTypeGROUPDN
	ACIv3BindTypeROLEDN
	ACIv3BindTypeSELFDN
	ACIv3BindTypeLDAPURL
)

/*
ACIv3BindKeyword constants are intended for singular use within an [ACIv3BindRule] instance.
*/
const (
	invalidACIv3BindKeyword ACIv3BindKeyword = iota // <invalid_bind_keyword>
	ACIv3BindUDN                                    // `userdn`
	ACIv3BindRDN                                    // `roledn`
	ACIv3BindGDN                                    // `groupdn`
	ACIv3BindUAT                                    // `userattr`
	ACIv3BindGAT                                    // `groupattr`
	ACIv3BindIP                                     // `ip`
	ACIv3BindDNS                                    // `dns`
	ACIv3BindDoW                                    // `dayofweek`
	ACIv3BindToD                                    // `timeofday`
	ACIv3BindAM                                     // `authmethod`
	ACIv3BindSSF                                    // `ssf`
)

/*
ACIv3TargetKeyword constants are intended for singular use within an [ACIv3TargetRuleItem] instance.
*/
const (
	invalidACIv3TargetKeyword ACIv3TargetKeyword = iota // <invalid_target_keyword>
	ACIv3Target                                         // 0x1, target
	ACIv3TargetTo                                       // 0x2, target_to
	ACIv3TargetAttr                                     // 0x3, targetattr
	ACIv3TargetCtrl                                     // 0x4, targetcontrol
	ACIv3TargetFrom                                     // 0x5, target_from
	ACIv3TargetScope                                    // 0x6, targetscope
	ACIv3TargetFilter                                   // 0x7, targetfilter
	ACIv3TargetAttrFilters                              // 0x8, targattrfilters (yes, "targ". As in "wild Klingon boars").
	ACIv3TargetExtOp                                    // 0x9, extop
)

/*
ACIv3Level uint16 constants are left-shifted to define a range of vertical (depth) [ACIv3BindRule] statements.
*/
const (
	invalidACIv3InheritanceLevel ACIv3InheritanceLevel = 0         //   0 - <no levels>
	ACIv3Level0                  ACIv3InheritanceLevel = 1 << iota //   1 - base  (0) (current Object)
	ACIv3Level1                                                    //   2 - one   (1) level below baseObject
	ACIv3Level2                                                    //   4 - two   (2) levels below baseObject
	ACIv3Level3                                                    //   8 - three (3) levels below baseObject
	ACIv3Level4                                                    //  16 - four  (4) levels below baseObject
	ACIv3Level5                                                    //  32 - five  (5) levels below baseObject
	ACIv3Level6                                                    //  64 - six   (6) levels below baseObject
	ACIv3Level7                                                    // 128 - seven (7) levels below baseObject
	ACIv3Level8                                                    // 256 - eight (8) levels below baseObject
	ACIv3Level9                                                    // 512 - nine  (9) levels below baseObject

	AllLevels ACIv3InheritanceLevel = ACIv3InheritanceLevel(2046) // ALL levels; one (1) through nine (9)
)

const (
	invalidCop ACIv3Operator = 0x0

	ACIv3Eq ACIv3Operator = 0x1 // "Equal To"
	ACIv3Ne ACIv3Operator = 0x2 // "Not Equal To"     !! USE WITH CAUTION !!
	ACIv3Lt ACIv3Operator = 0x3 // "Less Than"
	ACIv3Gt ACIv3Operator = 0x4 // "Greater Than"
	ACIv3Le ACIv3Operator = 0x5 // "Less Than Or Equal"
	ACIv3Ge ACIv3Operator = 0x6 // "Greater Than Or Equal"
)

/*
[AttributeOperation] constants are used to initialize and return [ACIv3AttributeFilter] instances based on one (1) of the possible two (2) constants defined below.
*/
const (
	noAOp      ACIv3AttributeOperation = iota
	ACIv3AddOp                         // add=
	ACIv3DelOp                         // delete=
)

const (
	brAnd aCIBindRuleTokenType = iota
	brOr
	brNot
	brParenOpen
	brParenClose
	brValue
	brOperator
)

const (
	trParenOpen aCITargetRuleTokenType = iota
	trParenClose
	trKeyword
	trOperator
	trValue
	trDelim
)

const (
	badATStr          = `<invalid_attribute_type>`
	badAVStr          = `<invalid_attribute_value>`
	badACIv3TRStr     = `<invalid_target_rule>`
	badACIv3BRStr     = `<invalid_bind_rule>`
	badACIv3BTStr     = `<invalid_bind_type>`
	badACIv3BKWStr    = `<invalid_bind_keyword>`
	badACIv3TKWStr    = `<invalid_target_keyword>`
	badACIv3InhStr    = `<invalid_inheritance>`
	badACIv3PermStr   = `<invalid_permission>`
	badDobrNotStr     = `<invalid_object_identifier>`
	badPBRStr         = `<invalid_permission_bind_rule>`
	badDoWStr         = `<invalid_days>`
	badToDStr         = `<invalid_timeofday>`
	badCopStr         = `<invalid_comparison_operator>`
	badACIv3IPAddrStr = `<invalid_address_list>`
	badACIv3FQDNStr   = `<invalid_fqdn_or_label>`
)

const (
	aCIBindRuleIDStr   = `bindRule`
	aCITargetRuleIDStr = `targetRule`
	pbrRuleIDStr       = `permissionBindRule`
	pbrRuleItemIDStr   = `permissionBindRuleItem`
)

const (
	fqdnMax  = 253
	labelMax = 63
)

/*
Day constants can be shifted into an instance of [ACIv3DayOfWeek], allowing effective expressions such as [Sun],[Tues]. See the [ACIv3DayOfWeek.Shift] and [ACIv3DayOfWeek.Unshift] methods.
*/
const (
	noDay ACIv3Day = 0         // 0 <invalid_day>
	Sun   ACIv3Day = 1 << iota // 1
	Mon                        // 2
	Tues                       // 4
	Wed                        // 8
	Thur                       // 16
	Fri                        // 32
	Sat                        // 64
)

var (
	authMap   map[int]ACIv3AuthenticationMethod
	authNames map[string]ACIv3AuthenticationMethod
)

/*
ACIv3AuthenticationMethodLowerCase allows control over the case folding of ACIv3AuthenticationMethod string representation.

A value of true shall force lowercase normalization, while a value of false (default) forces uppercase normalization.
*/
var ACIv3AuthenticationMethodLowerCase bool

/*
ACIv3AuthenticationMethod constants define all of the available LDAP authentication mechanisms recognized within the ACIv3 syntax honored by the package.

Please note that supported SASL mechanisms vary per implementation.
*/
const (
	noAuth         ACIv3AuthenticationMethod = iota // invalid
	ACIv3Anonymous                                  // 0
	ACIv3Simple                                     // 1
	ACIv3SSL                                        // 2
	ACIv3SASL                                       // 3
	ACIv3EXTERNAL                                   // 4
	ACIv3DIGESTMD5                                  // 5
	ACIv3GSSAPI                                     // 6
)

type aCIBindRuleTokenType int

func (r aCIBindRuleTokenType) isBooleanOperator() bool {
	return r == brAnd || r == brOr || r == brNot
}

type aCITargetRuleTokenType int

/*
ACIv3BindKeyword contains the value describing a particular [ACIv3Keyword] to be used within an [ACIv3BindRule].
*/
type ACIv3BindKeyword uint8

/*
ACIv3TargetKeyword contains the value describing a particular [ACIv3Keyword] to be used within an [ACIv3TargetRuleItem].
*/
type ACIv3TargetKeyword uint8

/*
ACIv3BindType describes one (1) of five (5) possible contexts used in certain [ACIv3BindRule] instances:

  - [ACIv3BindTypeUSERDN]
  - [ACIv3BindTypeGROUPDN]
  - [ACIv3BindTypeROLEDN]
  - [ACIv3BindTypeSELFDN]
  - [ACIv3BindTypeLDAPURL]
*/
type ACIv3BindType uint8

/*
String returns the string representation of the receiver instance of [ACIv3BindType].
*/
func (r ACIv3BindType) String() (b string) {
	b = badACIv3BTStr
	if kw, found := aCIBTMap[r]; found {
		b = kw
	}
	return
}

/*
Kind returns the static string literal `bindRule` identifying the instance as a [ACIv3BindKeyword].
*/
func (r ACIv3BindKeyword) Kind() string {
	return aCIBindRuleIDStr
}

func (r ACIv3BindKeyword) isACIv3Keyword() {}

func aCIKeywordIn(kw ACIv3Keyword, kws ...ACIv3Keyword) (in bool) {
	for _, k := range kws {
		if in = k.String() == kw.String(); in {
			break
		}
	}

	return
}

/*
Kind returns the static string literal `targetRule` identifying the instance as a [ACIv3TargetKeyword].
*/
func (r ACIv3TargetKeyword) Kind() string {
	return aCITargetRuleIDStr
}

func (r ACIv3TargetKeyword) isACIv3Keyword() {}

/*
String returns the string representation of the receiver instance of [ACIv3BindKeyword].
*/
func (r ACIv3BindKeyword) String() (k string) {
	k = badACIv3BKWStr
	if kw, found := aCIBindKeywordMap[r]; found {
		k = kw
	}
	return
}

/*
String returns the string representation of the receiver instance of [ACIv3TargetKeyword].
*/
func (r ACIv3TargetKeyword) String() (k string) {
	k = badACIv3TKWStr
	if kw, found := aCITargetKeywordMap[r]; found {
		k = kw
	}
	return
}

func assertATBTVBindKeyword(bkw ...any) (kw ACIv3BindKeyword) {
	if kw = ACIv3BindUAT; len(bkw) > 0 {
		switch tv := bkw[0].(type) {
		case ACIv3BindKeyword:
			if tv == ACIv3BindGAT {
				kw = tv
			}
		}
	}

	return
}

/*
matchTKW will return the matching ACIv3TargetKeyword constant for the input kw string value.
*/
func matchTKW(kw any) (k ACIv3TargetKeyword) {
	k = invalidACIv3TargetKeyword

	var keyword string
	switch tv := kw.(type) {
	case string:
		keyword = tv
	case ACIv3TargetKeyword:
		keyword = tv.String()
	default:
		return
	}

	for n, v := range aCITargetKeywordMap {
		if streqf(keyword, v) {
			k = n.(ACIv3TargetKeyword)
			break
		}
	}

	return
}

/*
matchBKW will return the matching BindKeyword constant for the input kw string value.
*/
func matchBKW(kw any) (k ACIv3BindKeyword) {
	k = invalidACIv3BindKeyword

	var keyword string
	switch tv := kw.(type) {
	case string:
		keyword = tv
	case ACIv3BindKeyword:
		keyword = tv.String()
	default:
		return
	}

	for n, v := range aCIBindKeywordMap {
		if streqf(keyword, v) {
			k = n.(ACIv3BindKeyword)
			break
		}
	}

	return
}

/*
matchBT will return the matching BindType constant for the input kw string value.
*/
func matchBT(kw string) ACIv3BindType {
	for k, v := range aCIBTMap {
		if streqf(kw, v) {
			return k
		}
	}

	return ACIv3BindType(0x0)
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3Operator) String() (cop string) {
	cop = badCopStr
	switch r {
	case ACIv3Eq:
		cop = `=`
	case ACIv3Ne:
		cop = `!=`
	case ACIv3Ge:
		cop = `>=`
	case ACIv3Gt:
		cop = `>`
	case ACIv3Le:
		cop = `<=`
	case ACIv3Lt:
		cop = `<`
	}

	return
}

/*
Description returns the string description for the receiver instance:

  - "Equal To"
  - "Not Equal To"
  - "Less Than"
  - "Greater Than"
  - "Less Than Or Equal"
  - "Greater Than Or Equal"

This method is largely for convenience, and many individuals may feel it only has any practical
applications in the areas of documentation, diagram creation or some other similar activity.

However, a prudent cybersecurity expert may argue that this method can be used to aid in the
(critical) area of proofreading newly-devised or modified access control statements. A person
could very easily mistake >= and <=, certainly if they're overworked or not paying attention.
One such mistake could spell disaster.

Additionally, use of this method as a means to auto-generate [Instruction] comments (for LDIF
configurations, or similar) can greatly help an admin more easily READ and UNDERSTAND the statements
in question.

See the [ACIv3Operator] const definitions for details.
*/
func (r ACIv3Operator) Description() (desc string) {
	desc = badCopStr
	switch r {
	case ACIv3Eq:
		desc = `Equal To`
	case ACIv3Ne:
		desc = `Not Equal To`
	case ACIv3Ge:
		desc = `Greater Than Or Equal`
	case ACIv3Gt:
		desc = `Greater Than`
	case ACIv3Le:
		desc = `Less Than Or Equal`
	case ACIv3Lt:
		desc = `Less Than`
	}

	return
}

/*
Context returns the contextual string name of the receiver instance:

  - "Eq"
  - "Ne"
  - "Lt"
  - "Gt"
  - "Le"
  - "Ge"
*/
func (r ACIv3Operator) Context() (ctx string) {
	ctx = badCopStr
	switch r {
	case ACIv3Eq:
		ctx = `Eq`
	case ACIv3Ne:
		ctx = `Ne`
	case ACIv3Ge:
		ctx = `Ge`
	case ACIv3Gt:
		ctx = `Gt`
	case ACIv3Le:
		ctx = `Le`
	case ACIv3Lt:
		ctx = `Lt`
	}

	return
}

/*
Valid returns an error instance following the process of verifying the receiver to be a known [ACIv3Operator] instance.  This does NOT, however, imply feasibility of use with any particular type in the creation of [ACIv3BindRule] or [ACIv3TargetRuleItem] instances.
*/
func (r ACIv3Operator) Valid() (err error) {
	if !isValidCopNumeral(int(r)) {
		err = badACIv3CopErr
	}

	return
}

/*
Compare shall resolve the input [ACIv3Operator] candidate (cop) and, if successful, shall perform an equality assertion between it and the receiver instance. The assertion result is returned as a bool instance.

In the case of the string representation of a given candidate input value, case-folding is not a significant factor.
*/
func (r ACIv3Operator) Compare(cop any) bool {
	switch tv := cop.(type) {
	case ACIv3Operator:
		return tv == r
	case int:
		return int(tv) == int(r)
	case string:
		return strInSlice(tv, []string{
			r.Description(),
			r.Context(),
			r.String(),
		})
	}

	return false
}

/*
isValidCopNumeral merely returns the Boolean evaluation result of a check to see whether integer x falls within a numerical range of one (1) through six (6).

This range represents the absolute minimum and maximum numerical values for any valid instance of the ACIv3Operator type (and, by necessity, the go-aci [ACIv3Operator] alias type as well).
*/
func isValidCopNumeral(x int) bool {
	return (1 <= x && x <= 6)
}

/*
keywordAllowsACIv3Operator returns a Boolean value indicative of whether ACIv3Keyword input value kw allows [ACIv3Operator] op for use in T/B rule instances.

Certain keywords, such as [ACIv3TargetScope], allow only certain operators, while others, such as [ACIv3BindSSF], allow the use of ALL operators.
*/
func keywordAllowsACIv3Operator(kw, op any) (allowed bool) {
	// identify the comparison operator,
	// save as cop var.
	var cop ACIv3Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case ACIv3Operator:
		cop = tv
	case int:
		cop = ACIv3Operator(tv)
	default:
		return
	}

	// identify the keyword, and pass it onto
	// the appropriate map search function.
	switch tv := kw.(type) {
	case string:
		if bkw := matchBKW(tv); bkw != ACIv3BindKeyword(0x0) {
			allowed = operatorAllowedPerKeyword(bkw, cop, aCIPermittedBindOperators)
		} else if tkw := matchTKW(tv); tkw != ACIv3TargetKeyword(0x0) {
			allowed = operatorAllowedPerKeyword(tkw, cop, aCIPermittedTargetOperators)
		}
	case ACIv3BindKeyword:
		allowed = operatorAllowedPerKeyword(tv, cop, aCIPermittedBindOperators)
	case ACIv3TargetKeyword:
		allowed = operatorAllowedPerKeyword(tv, cop, aCIPermittedTargetOperators)
	}

	return
}

/*
matchACIv3Cop reads the *string representation* of a ACIv3Operator instance and returns the appropriate ACIv3Operator constant.

A bogus ACIv3Operator (badCop, 0x0) shall be returned if a match was not made.
*/
func matchACIv3Cop(op string) (cop ACIv3Operator) {
	for _, v := range aCIOperatorMap {
		if strInSlice(op, []string{
			v.String(),
			v.Context(),
			v.Description(),
		}) {
			cop = v
			break
		}
	}

	return
}

func operatorAllowedPerKeyword(key ACIv3Keyword, cop ACIv3Operator, table map[ACIv3Keyword][]ACIv3Operator) (allowed bool) {
	// look-up the keyword within the permitted cop
	// map; if found, obtain slices of cops allowed
	// by said keyword.
	if cops, found := table[key]; found {
		// iterate the cops slice, attempting to perform
		// a match of the input cop candidate value and
		// the current cops slice [i].
		for i := 0; i < len(cops) && !allowed; i++ {
			if cop == cops[i] {
				allowed = true
			}
		}
	}

	return
}

//// BIND

/*
BindRuleItem is a qualifier of the [ACIv3BindRule] interface type,
and represents the core "atom" of any Bind Rule statement.

An instance of this type contains three (3) user-assigned
components, all of which are required:

  - A [ACIv3BindKeyword]; assigned via the [ACIv3BindRuleItem.SetKeyword] method
  - A [ACIv3Operator]; assigned via the [ACIv3BindRuleItem.SetOperator] method
  - An expression (value of any); assigned via the [ACIv3BindRuleItem.SetExpression] method
*/
type ACIv3BindRuleItem struct {
	*aCIBindRuleItem
}

/*
aCIBindRuleItem is the private embedded type found within,
viable instances of [ACIv3BindRuleItem].
*/
type aCIBindRuleItem struct {
	Keyword    ACIv3BindKeyword
	Operator   ACIv3Operator
	Expression any

	paren bool // leading/trailing parentheticals
	pad   bool // leading/trailing space char (inner parens)
	mvq   bool // multi-val quote scheme
}

/*
SetQuotationStyle allows the election of a particular multivalued quotation style offered by the various adopters of the ACIv3 syntax. In the context of a [ACIv3BindRule], this will only have a meaningful impact if the keyword for the receiver is one (1) of the following:

  - [ACIv3BindUDN]     (userdn)
  - [ACIv3BindRDN]     (roledn)
  - [ACIv3BindGDN]     (groupdn)

Additionally, the underlying type set as the expression value within the receiver MUST be a [ACIv3BindDistinguishedNames] instance with two (2) or more distinguished names within.

See the const definitions for [MultivalOuterQuotes] (default) and [MultivalSliceQuotes] for details.
*/
func (r ACIv3BindRuleItem) SetQuotationStyle(style int) ACIv3BindRule {
	if !r.IsZero() {
		switch r.Expression().(type) {
		case ACIv3BindDistinguishedName:
			switch r.Keyword() {
			case ACIv3BindUDN, ACIv3BindGDN, ACIv3BindRDN:
				r.aCIBindRuleItem.mvq = style == 0
			}
		}
	}

	return r
}

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[ACIv3BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r ACIv3BindRuleOr) SetQuotationStyle(_ int) ACIv3BindRule { return r }

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[ACIv3BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r ACIv3BindRuleAnd) SetQuotationStyle(_ int) ACIv3BindRule { return r }

/*
SetQuotationStyle performs no useful task, as the concept of setting a quotation
style applies only to instances of *[ACIv3BindRuleItem]. This method exists solely
to satisfy Go's interface signature requirements.
*/
func (r ACIv3BindRuleNot) SetQuotationStyle(_ int) ACIv3BindRule { return r }

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r ACIv3BindRuleItem) SetPaddingStyle(style int) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleItem.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r ACIv3BindRuleAnd) SetPaddingStyle(style int) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r ACIv3BindRuleOr) SetPaddingStyle(style int) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.pad = style > 0
	}

	return r
}

/*
SetPaddingStyle controls whitespace padding during the string representation process.

A value of 0 disables padding, while any other positive value enables padding.
*/
func (r ACIv3BindRuleNot) SetPaddingStyle(style int) ACIv3BindRule {
	if !r.IsZero() {
		r.ACIv3BindRule.SetPaddingStyle(style)
	}

	return r
}

/*
Kind returns the string literal "bindRuleItem".
*/
func (r ACIv3BindRuleItem) Kind() string {
	return `bindRuleItem`
}

/*
Kind returns the string literal "bindRuleAnd".
*/
func (r ACIv3BindRuleAnd) Kind() string {
	return `bindRuleAnd`
}

/*
Kind returns the string literal "bindRuleOr".
*/
func (r ACIv3BindRuleOr) Kind() string {
	return `bindRuleOr`
}

/*
Kind returns the string literal "bindRuleNot".
*/
func (r ACIv3BindRuleNot) Kind() string {
	return `bindRuleNot`
}

/*
Push performs no useful action, as this method exists solely
to satisfy Go's interface signature requirements.
*/
func (r ACIv3BindRuleItem) Push(_ ...any) ACIv3BindRule {
	return r
}

func (r ACIv3BindRuleItem) isBindRule() {} // differentiate from other interfaces
func (r ACIv3BindRuleAnd) isBindRule()  {} // differentiate from other interfaces
func (r ACIv3BindRuleOr) isBindRule()   {} // differentiate from other interfaces
func (r ACIv3BindRuleNot) isBindRule()  {} // differentiate from other interfaces

/*
ACIv3BindRuleAnd qualifies the [ACIv3BindRule] interface type and implements
a "BOOLEAN AND" multi-valued slice type in which ALL conditions must
evaluate as true to be considered a match.
*/
type ACIv3BindRuleAnd struct {
	*aCIBindRuleSlice
}

/*
aCIBindRuleSlice is the private embedded type found within instances
of [ACIv3BindRuleAnd] and [ACIv3BindRuleOr].
*/
type aCIBindRuleSlice struct {
	slice []ACIv3BindRule
	paren bool
	kind  string
	pad   bool
}

/*
ACIv3BindRuleOr qualifies the [ACIv3BindRule] interface type and implements
a "BOOLEAN OR" multi-valued slice type in which ONE (1) OR MORE
conditions must evaluate as true to be considered a match.
*/
type ACIv3BindRuleOr struct {
	*aCIBindRuleSlice
}

/*
ACIv3BindRuleNot qualifies the [ACIv3BindRule] interface type and implements
a "BOOLEAN NOT" (negated) type in which NONE of the conditions must
evaluate as true to be considered a match.
*/
type ACIv3BindRuleNot struct {
	*aCIBindRuleNot
}

type aCIBindRuleNot struct {
	ACIv3BindRule
}

/*
Push appends the input instance(s) of [ACIv3BindRule] to the receiver instance.
*/
func (r ACIv3BindRuleAnd) Push(x ...any) ACIv3BindRule {
	if r.IsZero() {
		r = ACIv3BindRuleAnd{&aCIBindRuleSlice{}}
	}

	var err error
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br ACIv3BindRule
				if br, err = parseACIv3BindRuleTokens(tkz); err == nil {
					r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, br)
				}
			}
		case ACIv3BindRule:
			if err = tv.Valid(); err == nil {
				r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, tv)
			}
		}
	}

	return r
}

/*
Push appends the input instance(s) of [ACIv3BindRule] to the receiver instance.
*/
func (r ACIv3BindRuleOr) Push(x ...any) ACIv3BindRule {
	if r.IsZero() {
		r = ACIv3BindRuleOr{&aCIBindRuleSlice{}}
	}

	var err error
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br ACIv3BindRule
				if br, err = parseACIv3BindRuleTokens(tkz); err == nil {
					r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, br)
				}
			}
		case ACIv3BindRule:
			if err = tv.Valid(); err == nil {
				r.aCIBindRuleSlice.slice = append(r.aCIBindRuleSlice.slice, tv)
			}
		}
	}

	return r
}

/*
Push assigns the input instance of [ACIv3BindRule] to the receiver
instance. Unlike other Push methods, this does not append.
*/
func (r ACIv3BindRuleNot) Push(x ...any) ACIv3BindRule {
	if r.aCIBindRuleNot == nil {
		r.aCIBindRuleNot = &aCIBindRuleNot{}
	}

	if len(x) > 0 {
		var err error
		switch tv := x[0].(type) {
		case string:
			var iter int
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				var br ACIv3BindRule
				if br, err = parseACIv3BindRuleGroup(tkz, &iter); err == nil {
					r.aCIBindRuleNot.ACIv3BindRule = br
				}
			}
		case ACIv3BindRule:
			k := tv.Kind()
			err = tv.Valid()
			if err == nil && strInSlice(k, []string{`bindRuleAnd`, `bindRuleOr`, `bindRuleItem`}) {
				r.aCIBindRuleNot.ACIv3BindRule = tv
			}
		}
	}

	return r
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3BindRuleItem) String() (s string) {
	s = badACIv3BRStr
	if r.IsZero() {
		return s
	}

	// Try to coax a string out of the value.
	var raw string
	switch tv := r.Expression().(type) {
	case ACIv3BindDistinguishedName:
		raw = tv.string(r.aCIBindRuleItem.mvq, r.aCIBindRuleItem.pad)
	default:
		if meth := getStringer(tv); meth != nil {
			raw = meth()
		} else {
			return s
		}
	}

	if !(hasPfx(raw, `"`) && hasSfx(raw, `"`)) {
		raw = `"` + raw + `"`
	}

	var pad string
	if r.pad {
		pad = ` `
	}

	s = r.Keyword().String() + pad +
		r.Operator().String() + pad + raw

	if r.paren {
		s = `(` + pad + s + pad + `)`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3BindRuleAnd) String() string {
	return r.aCIBindRuleSlice.aCIBindRuleSliceString("AND")
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3BindRuleOr) String() string {
	return r.aCIBindRuleSlice.aCIBindRuleSliceString("OR")
}

func (r *aCIBindRuleSlice) aCIBindRuleSliceString(k string) (s string) {
	s = `invalidBindRule` + k
	if r == nil {
		return
	}

	if len(r.slice) > 0 {
		var _s []string
		for i := 0; i < len(r.slice); i++ {
			_s = append(_s, r.slice[i].String())
		}

		var bop string = ` ` + k + ` `
		var pad string
		if r.pad {
			pad = ` `
		}

		s = join(_s, bop)

		if r.paren {
			s = `(` + pad + s + pad + `)`
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3BindRuleNot) String() (s string) {
	s = `invalidBindRuleNot`
	if r.ACIv3BindRule != nil {
		s = `NOT ` + r.ACIv3BindRule.String()
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3BindRuleItem) IsZero() bool {
	return r.aCIBindRuleItem == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3BindRuleAnd) IsZero() bool {
	return r.aCIBindRuleSlice == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3BindRuleOr) IsZero() bool {
	return r.aCIBindRuleSlice == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3BindRuleNot) IsZero() bool {
	return r.aCIBindRuleNot == nil
}

/*
Len returns an integer length of one (1) if the instance has
been initialized, and an integer length of zero (0) if not
initialized.

This method exists solely to satisfy Go's interface signature
requirements and is not necessary to use upon instances of this
type.
*/
func (r ACIv3BindRuleItem) Len() int {
	var l int
	if &r != nil {
		l++
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3BindRuleAnd) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIBindRuleSlice.slice)
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3BindRuleOr) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIBindRuleSlice.slice)
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3BindRuleNot) Len() int {
	var l int
	if r.ACIv3BindRule != nil {
		l = r.ACIv3BindRule.Len()
	}

	return l
}

/*
Index returns the Nth underlying slice index, if present.

This type exports this method solely to satisfy Go's interface
signature requirements and is not necessary to use upon instances
of this type. If executed, this method returns the receiver
instance.
*/
func (r ACIv3BindRuleItem) Index(_ int) ACIv3BindRule { return r }

/*
Index returns the Nth underlying [ACIv3BindRule] slice index, if present.
*/
func (r ACIv3BindRuleAnd) Index(idx int) ACIv3BindRule {
	var br ACIv3BindRule = badACIv3BindRule
	if 0 <= idx && idx < r.Len() {
		br = r.aCIBindRuleSlice.slice[idx]
	}

	return br
}

/*
Index returns the Nth underlying [ACIv3BindRule] slice index, if present.
*/
func (r ACIv3BindRuleOr) Index(idx int) ACIv3BindRule {
	var br ACIv3BindRule = badACIv3BindRule
	if 0 <= idx && idx < r.Len() {
		br = r.aCIBindRuleSlice.slice[idx]
	}

	return br
}

/*
Index returns the Nth underlying [ACIv3BindRule] slice index, if present.

Note that, in the case of instances of this type, this method is only
meaningful if the underlying [ACIv3BindRule] qualifier type is an instance
of [ACIv3BindRuleAnd] or [ACIv3BindRuleOr].
*/
func (r ACIv3BindRuleNot) Index(idx int) ACIv3BindRule {
	var br ACIv3BindRule = badACIv3BindRule
	if r.ACIv3BindRule != nil {
		k := r.ACIv3BindRule.Kind()
		if k == `bindRuleAnd` || k == `bindRuleOr` {
			if 0 <= idx && idx < r.ACIv3BindRule.Len() {
				br = r.ACIv3BindRule.Index(idx)
			}
		}
	}

	return br
}

/*
Valid returns an error instance which, when non-nil,
will indicate a logical flaw, such a missing component
of a [ACIv3BindRuleItem] qualifier, or some other issue.
*/
func (r ACIv3BindRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = errorTxt("Invalid bind rule (ITEM): is zero")
		return
	}

	for _, ok := range []bool{
		r.Keyword() != invalidACIv3BindKeyword,
		r.Operator() != 0x0,

		// TODO:expand on this logic to limit validity
		// to high-level interface qualifiers only, or
		// raw string values.
		r.Expression() != nil,
	} {
		if !ok {
			err = errorTxt("Invalid bind rule (ITEM): Missing bindRule keyword, operator or the expr value is bogus")
			break
		}
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a flaw in an instance residing at a particular
slice index.
*/
func (r ACIv3BindRuleAnd) Valid() (err error) {
	if r.IsZero() {
		err = errorTxt("Invalid bind rule (AND): is zero")
	} else {
		err = r.aCIBindRuleSlice.Valid()
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a flaw in an instance residing at a particular
slice index.
*/
func (r ACIv3BindRuleOr) Valid() (err error) {
	if r.IsZero() {
		err = errorTxt("Invalid bind rule (OR): is zero")
	} else {
		err = r.aCIBindRuleSlice.Valid()
	}

	return
}

/*
Valid returns an error instance which, when non-nil, will
indicate a logical flaw, such as a nil or zero length
[ACIv3BindRule] instance, a missing component of a [ACIv3BindRuleItem]
qualifier, or some other issue.
*/
func (r ACIv3BindRuleNot) Valid() (err error) {
	if r.IsZero() {
		err = errorTxt("Invalid bind rule (NOT): is zero")
	} else {
		err = r.ACIv3BindRule.Valid()
	}

	return
}

/*
Valid is a private method executed by the [ACIv3BindRuleAnd.Valid]
and [ACIv3BindRuleOr.Valid] methods.
*/
func (r *aCIBindRuleSlice) Valid() (err error) {
	if len(r.slice) == 0 {
		err = errorTxt("slice rule is zero length")
		return
	}
	for idx, rule := range r.slice {
		if err = rule.Valid(); err != nil {
			// Reveal the bogus slice
			// index to the user...
			err = errorTxt(err.Error() + " at or nested within bindRule index " + itoa(idx))
			break
		}
	}

	return
}

/*
ACIv3BindRule implements an interface qualifier type for instances
of any of the following types:

  - [ACIv3BindRuleItem]
  - [ACIv3BindRuleAnd]
  - [ACIv3BindRuleOr]
  - [ACIv3BindRuleNot]
*/
type ACIv3BindRule interface {
	// Kind returns the string literal "bindRuleItem",
	// "bindRuleAnd", "bindRuleOr" or "bindRuleNot"
	// depending on the underlying qualifier type.
	Kind() string

	// String returns the string representation
	// of the receiver instance.
	String() string

	// Len returns the integer length of the receiver
	// instance.

	// Note that if the underlying qualifier type is an
	// instance of [ACIv3BindRuleItem], an value or zero (0)
	// or one (1) shall always be returned, depending on
	// whether or not the instance is nil.
	Len() int

	// IsZero returns a Boolean value indicative of a
	// nil underlying qualifier type instance.
	IsZero() bool

	// Push appends one (1) or more qualifier type
	// instances of [ACIv3BindRule] to the receiver instance.
	//
	// Note this only has any meaningful effect if the
	// underlying qualifier type is an instance of
	// [ACIv3BindRuleAnd] or [ACIv3BindRuleOr].
	Push(...any) ACIv3BindRule

	// Index returns the Nth underlying slice value found
	// within the underlying qualifier type instance.
	//
	// Note this only has any meaningful effect if the
	// underlying qualifier type is an instance of
	// [ACIv3BindRuleAnd] or [ACIv3BindRuleOr].
	Index(int) ACIv3BindRule

	// SetParen assigns the input Boolean value to the
	// receiver instance.  A value of true shall serve
	// to encapsulate subsequent string representations
	// in parenthesis characters, namely "(" and ")".
	// A value of false performs no such encapsulation
	// and is the default value.
	SetParen(bool) ACIv3BindRule

	// SetQuotationStyle controls whether multivalued
	// values of specific types will be individually
	// quoted during string representation. A value of
	// zero (0) results in individually quoted values,
	// while any other value encapsulates all values
	// in a single pair of quotes. Note that this shall
	// only have an effect if there are two (2) or more
	// values present.
	SetQuotationStyle(int) ACIv3BindRule

	// SetPaddingStyle controls whether whitespace
	// padding is used during string representation. A
	// value of zero (0) disables padding, while any
	// other positive value enables padding.
	SetPaddingStyle(int) ACIv3BindRule

	// IsParen returns a Boolean value indicative of
	// whether the underlying qualifier type instance
	// is configured to encapsulate subsequent string
	// representations within parenthetical characters.
	IsParen() bool

	// Valid returns an error instance which, when non-nil,
	// will indicate a logical flaw, such as a nil or zero
	// length [ACIv3BindRule] instance, a missing component of
	// a [ACIv3BindRuleItem] qualifier, or some other issue.
	Valid() error

	// Compare returns a Boolean value indicative of a
	// SHA-1 comparison between the receiver and input
	// value x.
	//Compare(any) bool

	// differentiate from other interface types of a
	// similar design.
	isBindRule()
}

/*
ACIv3BindRuleMethods contains one (1) or more instances of [ACIv3BindRuleMethod], representing a particular [ACIv3BindRule] "builder" method for execution by the caller.

See the Operators method extended through all eligible types for further details.
*/
type ACIv3BindRuleMethods struct {
	*aCIBindRuleFuncMap
}

/*
newACIv3BindRuleMethods populates an instance of *aCIBindRuleFuncMap, which
is embedded within the return instance of ACIv3BindRuleMethods.
*/
func newACIv3BindRuleMethods(m aCIBindRuleFuncMap) ACIv3BindRuleMethods {
	M := make(aCIBindRuleFuncMap, len(m))
	for k, v := range m {
		M[k] = v
	}

	return ACIv3BindRuleMethods{&M}
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r ACIv3BindRuleItem) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleItem.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r ACIv3BindRuleAnd) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleSlice.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r ACIv3BindRuleOr) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleSlice.paren
	}

	return
}

/*
IsParen returns a Boolean value indicative of the receiver
instance being in a parenthetical state.
*/
func (r ACIv3BindRuleNot) IsParen() (is bool) {
	if !r.IsZero() {
		is = r.aCIBindRuleNot.ACIv3BindRule.IsParen()
	}

	return
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r ACIv3BindRuleItem) SetParen(p bool) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleItem.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r ACIv3BindRuleAnd) SetParen(p bool) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r ACIv3BindRuleOr) SetParen(p bool) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleSlice.paren = p
	}

	return r
}

/*
SetParen declares whether the receiver instance is parenthetical.

A value of true engages parenthetical encapsulation during the
string representation process.
*/
func (r ACIv3BindRuleNot) SetParen(p bool) ACIv3BindRule {
	if !r.IsZero() {
		r.aCIBindRuleNot.ACIv3BindRule.IsParen()
	}

	return r
}

/*
Index calls the input index (idx) within the internal structure of the receiver instance. If found, an instance of [ACIv3Operator] and its accompanying [ACIv3BindRuleMethod] instance are returned.

Valid input index types are integer (int), [ACIv3Operator] constant or string identifier. In the case of a string identifier, valid values are as follows:

  - For [ACIv3Eq] (1): `=`, `ACIv3Eq`, `Equal To`
  - For [ACIv3Ne] (2): `!=`, `ACIv3Ne`, `Not Equal To`
  - For [ACIv3Lt] (3): `>`, `ACIv3Lt`, `Less Than`
  - For [ACIv3Le] (4): `>=`, `ACIv3Le`, `Less Than Or Equal`
  - For [ACIv3Gt] (5): `<`, `ACIv3Gt`, `Greater Than`
  - For [ACIv3Ge] (6): `<=`, `ACIv3Ge`, `Greater Than Or Equal`

Case is not significant in the string matching process.

Please note that use of this method by way of integer or [ACIv3Operator] values utilizes fewer resources than a string lookup.

See the [ACIv3Operator.Context], [ACIv3Operator.String] and [ACIv3Operator.Description] methods for accessing the above string values easily.

If the index was not matched, an invalid [ACIv3Operator] is returned alongside a nil [ACIv3BindRuleMethod]. This will also apply to situations in which the type instance which crafted the receiver is uninitialized, or is in an otherwise aberrant state.
*/
func (r ACIv3BindRuleMethods) Index(idx any) (ACIv3Operator, ACIv3BindRuleMethod) {
	return r.index(idx)
}

/*
index is a private method called by ACIv3BindRuleMethods.Index.
*/
func (r ACIv3BindRuleMethods) index(idx any) (cop ACIv3Operator, meth ACIv3BindRuleMethod) {
	if r.IsZero() {
		return
	}
	cop = invalidCop

	// perform a type switch upon the input
	// index type
	switch tv := idx.(type) {

	case ACIv3Operator:
		// cast cop as an int, and make recursive
		// call to this function.
		return r.Index(int(tv))

	case int:
		var found bool
		if meth, found = (*r.aCIBindRuleFuncMap)[ACIv3Operator(tv)]; found {
			cop = ACIv3Operator(tv)
			return
		}

	case string:
		cop, meth = rangeBindRuleFuncMap(tv, r.aCIBindRuleFuncMap)
	}

	return
}

func rangeBindRuleFuncMap(candidate string, fm *aCIBindRuleFuncMap) (cop ACIv3Operator, meth ACIv3BindRuleMethod) {
	// iterate all map entries, and see if
	// input string value matches the value
	// returned by these three (3) methods:
	for k, v := range *fm {
		if strInSlice(candidate, []string{
			k.String(),      // e.g.: "="
			k.Context(),     // e.g.: "ACIv3Eq"
			k.Description(), // e.g.: "Equal To"
		}) {
			cop = k
			meth = v
			break
		}
	}

	return
}

/*
BindDistinguishedName returns an instance of [ACIv3BindDistinguishedName] alongside an error
following an attempt to marshal the input arguments.

If no arguments are provided, a bogus instance is returned.

The first argument must be a single [ACIv3BindKeyword], which MUST be one of [ACIv3BindUDN],
[ACIv3BindGDN] or [ACIv3BindRDN].

All subsequent arguments must be any of the following:

  - String-based DNs, which may or may not include wildcard or substring patterns, or ...
  - Proper instances of [DistinguishedName]

In the case of a string-based DN with or without matching patterns, the ACIv3-required prefix
of "ldap:///" need not be specified.
*/
func (r NetscapeACIv3) BindDistinguishedName(x ...any) (ACIv3BindDistinguishedName, error) {
	return marshalACIv3BindDistinguishedName(x...)
}

func marshalACIv3BindDistinguishedName(x ...any) (bdn ACIv3BindDistinguishedName, err error) {
	var bkw ACIv3BindKeyword

	kwOK := func(bkw ACIv3BindKeyword) error {
		var err error
		if !aCIKeywordIn(bkw, ACIv3BindUDN, ACIv3BindGDN, ACIv3BindRDN) {
			err = badACIv3KWErr
		}
		return err
	}

	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			bkw = matchBKW(tv)
		case ACIv3BindKeyword:
			bkw = tv
		}

		if err = kwOK(bkw); err == nil {
			bdn.ACIv3BindKeyword = bkw
			bdn.aCIDistinguishedName = &aCIDistinguishedName{}
			if len(x) > 1 {
				err = bdn.aCIDistinguishedName.push(x[1:]...)
			}
		}
	}

	return bdn, err
}

/*
TargetDistinguishedName returns an instance of [ACIv3TargetDistinguishedName] alongside an error
following an attempt to marshal the input arguments.

If no arguments are provided, a bogus instance is returned.

The first argument must be a single [ACIv3TargetKeyword] or its string equivalent, which MUST be
one of [ACIv3Target], [ACIv3TargetTo] or [ACIv3TargetFrom].

All subsequent arguments must be any of the following:

  - String-based DNs, which may or may not include wildcard or substring patterns, or ...
  - Proper instances of [DistinguishedName]

In the case of a string-based DN with or without matching patterns, the ACIv3-required prefix
of "ldap:///" need not be specified.
*/
func (r NetscapeACIv3) TargetDistinguishedName(x ...any) (ACIv3TargetDistinguishedName, error) {
	return marshalACIv3TargetDistinguishedName(x...)
}

func marshalACIv3TargetDistinguishedName(x ...any) (tdn ACIv3TargetDistinguishedName, err error) {
	var tkw ACIv3TargetKeyword

	kwOK := func(tkw ACIv3TargetKeyword) (err error) {
		if !aCIKeywordIn(tkw, ACIv3Target, ACIv3TargetTo, ACIv3TargetFrom) {
			err = badACIv3KWErr
		}
		return err
	}

	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			tkw = matchTKW(tv)
		case ACIv3TargetKeyword:
			tkw = tv
		}

		if err = kwOK(tkw); err == nil {
			tdn.ACIv3TargetKeyword = tkw
			tdn.aCIDistinguishedName = &aCIDistinguishedName{}
			if len(x) > 1 {
				err = tdn.aCIDistinguishedName.push(x[1:]...)
			}
		}
	}

	return tdn, err
}

/*
Attribute returns an instance of [ACIv3Attribute] alongside an error following an
attempt to parse x into one (1) or more attribute type OIDs, whether as numeric or
descriptor values.
*/
func (r NetscapeACIv3) Attribute(x ...any) (ACIv3Attribute, error) {
	return marshalACIv3Attribute(x...)
}

func marshalACIv3Attribute(x ...any) (ACIv3Attribute, error) {
	var at ACIv3Attribute = ACIv3Attribute{&aCIAttribute{}}
	err := at.push(x...)
	return at, err
}

/*
BindRuleAnd returns an instance of [ACIv3BindRule], qualified via an underlying
[ACIv3BindRuleAnd] instance.

Zero (0) or more [ACIv3BindRule] qualifier type instances may be input
for immediate addition to the return value.
*/
func (r NetscapeACIv3) BindRuleAnd(x ...any) (ACIv3BindRule, error) {
	br := ACIv3BindRuleAnd{&aCIBindRuleSlice{}}
	return br.Push(x...), nil
}

/*
BindRuleOr returns an instance of [ACIv3BindRule], qualified via an underlying
[ACIv3BindRuleOr] instance.

Zero (0) or more [ACIv3BindRule] qualifier type instances may be input
for immediate addition to the return value.
*/
func (r NetscapeACIv3) BindRuleOr(x ...any) (ACIv3BindRule, error) {
	br := ACIv3BindRuleOr{&aCIBindRuleSlice{}}
	return br.Push(x...), nil
}

/*
BindRuleNot returns a negated instance of [ACIv3BindRule], qualified via an
underlying [ACIv3BindRuleNot] instance.

Note that up to one (1) [ACIv3BindRule] qualifier type instance may be set
within instances of this type. An instance of [ACIv3BindRuleNot] is ineligible
for assignment.
*/
func (r NetscapeACIv3) BindRuleNot(x ...any) (ACIv3BindRule, error) {
	return ACIv3BindRuleNot{newACIv3BindRuleNot(x...)}, nil
}

func newACIv3BindRuleNot(x ...any) (r *aCIBindRuleNot) {
	r = &aCIBindRuleNot{}

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			if tkz, err := tokenizeACIv3BindRule(tv); err == nil {
				var z ACIv3BindRule
				z, err = parseACIv3BindRuleTokens(tkz)
				if err == nil && z.Kind() != `bindRuleNot` {
					r.ACIv3BindRule = z
				}
			}
		case ACIv3BindRule:
			if tv.Kind() != `bindRuleNot` {
				r.ACIv3BindRule = tv
			}
		}
	}

	return
}

/*
BindRuleItem initialized, populates and returns an instance of [ACIv3BindRule],
qualified by an underlying *[ACIv3BindRuleItem] instance.
*/
func (r NetscapeACIv3) BindRuleItem(x ...any) (ACIv3BindRule, error) {
	var (
		bri ACIv3BindRuleItem = ACIv3BindRuleItem{&aCIBindRuleItem{}}
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			err = bri.parse(tv)
		case ACIv3BindKeyword:
			if matchBKW(tv) != 0x0 {
				if len(x) == 3 {
					if _, ok := x[1].(ACIv3Operator); !ok {
						err = badACIv3BRErr
					} else {
						return newACIv3BindRuleItem(x[0], x[1], x[2]), err
					}
				}
			}
		default:
			err = badACIv3TRErr
		}
	}

	return bri, err
}

func (r *ACIv3BindRuleItem) parse(x string) (err error) {
	var tkz []aCIBindRuleToken
	if tkz, err = tokenizeACIv3BindRule(x); len(tkz) >= 3 && err == nil {
		var b ACIv3BindRule
		if b, err = parseACIv3BindRuleTokens(tkz); err == nil {
			*r, _ = b.(ACIv3BindRuleItem)
		}
	}

	return err
}

func initACIv3BindRuleItem() ACIv3BindRuleItem {
	return ACIv3BindRuleItem{&aCIBindRuleItem{
		Keyword:  invalidACIv3BindKeyword,
		Operator: invalidCop,
	}}
}

func newACIv3BindRuleItem(kw, op any, ex ...any) ACIv3BindRuleItem {
	return initACIv3BindRuleItem().
		SetKeyword(kw).(ACIv3BindRuleItem).
		SetOperator(op).(ACIv3BindRuleItem).
		SetExpression(ex...).(ACIv3BindRuleItem)
}

/*
SetKeyword assigns [ACIv3Keyword] kw to the receiver instance.
*/
func (r ACIv3BindRuleItem) SetKeyword(kw any) ACIv3BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	switch tv := kw.(type) {
	case string:
		r.aCIBindRuleItem.Keyword = matchBKW(tv)
	case ACIv3BindKeyword:
		r.aCIBindRuleItem.Keyword = tv
	}

	return r
}

/*
SetOperator assigns [ACIv3Operator] op to the receiver
instance.
*/
func (r ACIv3BindRuleItem) SetOperator(op any) ACIv3BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	// assert underlying comparison operator.
	var cop ACIv3Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case ACIv3Operator:
		cop = tv
	}

	// For security reasons, only assign comparison
	// operator if it is Eq or Ne.
	if 0x0 < cop && cop <= 0x6 {
		r.aCIBindRuleItem.Operator = cop
	}

	return r
}

/*
SetExpression assigns value expr to the receiver instance.
*/
func (r ACIv3BindRuleItem) SetExpression(expr ...any) ACIv3BindRule {
	if r.aCIBindRuleItem == nil {
		r.aCIBindRuleItem = initACIv3BindRuleItem().aCIBindRuleItem
	}

	// Constrain to specific value types per keyword
	if value, err := assertBindValueByKeyword(r.aCIBindRuleItem.Keyword, expr...); err == nil {
		r.aCIBindRuleItem.Expression = value
	}

	return r
}

/*
Contains returns a Boolean value indicative of whether the specified [ACIv3Operator], which may be expressed as a string, int or native [ACIv3Operator], is allowed for use by the type instance that created the receiver instance. This method offers a convenient alternative to the use of the Index method combined with an assertion value (such as ACIv3Eq, ACIv3Ne, "=", "Greater Than", et al).

In other words, if one uses the [FQDN]'s BRM method to create an instance of [ACIv3BindRuleMethods], feeding Gt (Greater Than) to this method shall return false, as mathematical comparison does not apply to instances of the [FQDN] type.
*/
func (r ACIv3BindRuleMethods) Contains(cop any) bool {
	c, _ := r.index(cop)
	return c.Valid() == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3BindRuleMethods) IsZero() bool {
	return r.aCIBindRuleFuncMap == nil
}

/*
Valid returns the first encountered error returned as a result of execution of the first available [ACIv3BindRuleMethod] instance. This is useful in cases where a user wants to see if the desired instance(s) of [ACIv3BindRuleMethod] will produce a usable result.
*/
func (r ACIv3BindRuleMethods) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
		return
	}

	// ACIv3Eq is always available for all eligible
	// types, so let's use that unconditionally.
	// If any one method works, then all of them
	// will work.
	_, meth := r.Index(ACIv3Eq)
	err = meth().Valid()
	return
}

/*
Len returns the integer length of the receiver. Note that the return value will NEVER be less than zero (0) nor greater than six (6).
*/
func (r ACIv3BindRuleMethods) Len() int {
	var l int
	if !r.IsZero() {
		l = len((*r.aCIBindRuleFuncMap))
	}

	return l
}

/*
BindRuleMethod is the closure signature for methods used to build new instances of [ACIv3BindRule].

The signature is qualified by methods extended through all eligible types defined in this package.

Note that certain types only support a subset of the above list. Very few types support all of the above.
*/
type ACIv3BindRuleMethod func() ACIv3BindRule

/*
aCIBindRuleFuncMap is a private type intended to be used within instances of [ACIv3BindRuleMethods].
*/
type aCIBindRuleFuncMap map[ACIv3Operator]ACIv3BindRuleMethod

/*
Keyword returns the [ACIv3BindKeyword] value currently set within the receiver instance.
*/
func (r ACIv3BindRuleItem) Keyword() ACIv3BindKeyword {
	var bkw ACIv3BindKeyword = invalidACIv3BindKeyword
	if &r != nil {
		bkw = r.aCIBindRuleItem.Keyword
	}

	return bkw
}

/*
Operator returns the [ACIv3Operator] value currently set within the receiver instance.
*/
func (r ACIv3BindRuleItem) Operator() ACIv3Operator {
	var cop ACIv3Operator = invalidCop
	if &r != nil {
		cop = r.aCIBindRuleItem.Operator
	}

	return cop
}

/*
Expression returns the underlying expression value currently set within the receiver instance.
*/
func (r ACIv3BindRuleItem) Expression() any {
	var val any
	if r.aCIBindRuleItem != nil {
		val = r.aCIBindRuleItem.Expression
	}

	return val
}

/*
BindRule returns an instance of [ACIv3BindRule] alongside an error following an attempt to
parse string x as a qualifying instance of [ACIv3BindRuleItem], [ACIv3BindRuleAnd], [ACIv3BindRuleOr]
or [ACIv3BindRuleNot].
*/
func (r NetscapeACIv3) BindRule(x ...any) (ACIv3BindRule, error) {
	var (
		br  ACIv3BindRule
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			var tkz []aCIBindRuleToken
			if tkz, err = tokenizeACIv3BindRule(tv); err == nil {
				br, err = parseACIv3BindRuleExpression(tkz)
			}
		}
	}

	return br, err
}

type aCIBindRuleToken struct {
	Type  aCIBindRuleTokenType
	Value string
}

type aCITargetRuleToken struct {
	Type  aCITargetRuleTokenType
	Value string
}

func tokenizeACIv3BindRuleBooleanOperator(input string, tkz []aCIBindRuleToken) []aCIBindRuleToken {
	switch uc(input) {
	case "AND":
		tkz = append(tkz, aCIBindRuleToken{Type: brAnd, Value: input})
	case "OR":
		tkz = append(tkz, aCIBindRuleToken{Type: brOr, Value: input})
	case "NOT":
		tkz = append(tkz, aCIBindRuleToken{Type: brNot, Value: input})
	default:
		tkz = append(tkz, aCIBindRuleToken{Type: brValue, Value: input})
	}

	return tkz
}

/*
tokenizeACIv3BindRule tokenizes input into slices of aCIBindRuleToken.
*/
func tokenizeACIv3BindRule(input string) (tkz []aCIBindRuleToken, err error) {
	var tokens []aCIBindRuleToken
	bld := newStrBuilder()

	flush := func() {
		if bld.Len() > 0 {
			tokens = append(tokens, tokenizeACIv3BindRuleBooleanOperator(bld.String(), tkz)...)
			bld.Reset()
		}
	}

	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch ch {
		case '"':
			flush() // finish any pending token
			i++     // skip the starting quote
			for ; i < len(input) && input[i] != '"'; i++ {
				bld.WriteByte(input[i])
			}
			tokens = append(tokens, aCIBindRuleToken{Type: brValue, Value: bld.String()})
			bld.Reset()
		case '(':
			flush()
			tokens = append(tokens, aCIBindRuleToken{Type: brParenOpen, Value: "("})
		case ')':
			flush()
			tokens = append(tokens, aCIBindRuleToken{Type: brParenClose, Value: ")"})
		default:
			if isWHSP(rune(ch)) {
				flush()
			} else if ch == '=' {
				flush()
				bld.WriteByte(ch)
			} else if runeInSlice(rune(ch), []rune{'>', '<', '!'}) {
				flush()
				bld.WriteByte(ch)
				// If the next character is '=' then include it.
				if i+1 < len(input) && input[i+1] == '=' {
					bld.WriteByte(input[i+1])
					i++
				}
			} else {
				bld.WriteByte(ch)
			}
		}
	}
	flush()

	tkz, err = combineACIv3BindRuleTokens(tokens)

	return
}

func combineACIv3BindRuleTokens(tokens []aCIBindRuleToken) (combined []aCIBindRuleToken, err error) {
	// Combine "AND" immediately followed by "NOT" into a single operator token.
	for i := 0; i < len(tokens); {
		if tokens[i].Type == brAnd && i+1 < len(tokens) && tokens[i+1].Type == brNot {
			combined = append(combined, aCIBindRuleToken{Type: brNot, Value: "AND NOT"})
			i += 2 // 1 extra for "NOT"
		} else {
			combined = append(combined, tokens[i])
			i++
		}
	}

	// Ensure none of the tokens are empty, which would
	// almost certainly indicate a tokenization error of
	// bogus input.
	for _, tk := range combined {
		if tk.Value == "" {
			err = badACIv3BRTokenErr
			break
		}
	}

	return combined, err
}

/*
TargetRule returns an instance of [ACIv3TargetRule] alongside an error following an attempt to
parse raw as one (1) or more instance of [ACIv3TargetRuleItem].
*/
func (r NetscapeACIv3) TargetRule(x ...any) (ACIv3TargetRule, error) {
	var (
		tr  ACIv3TargetRule = ACIv3TargetRule{&aCITargetRule{}}
		err error
	)

	if len(x) > 0 {
		tr.Push(x...)
	}

	return tr, err
}

func (r *ACIv3TargetRule) parse(x string) (err error) {

	var tkz []aCITargetRuleToken
	if tkz, err = tokenizeACIv3TargetRule(x); err != nil {
		return
	} else if len(tkz) < 5 {
		err = errorTxt("unexpected number of tokens; any number of targetRuleItem tokens MUST ALWAYS be 5 <=")
		return
	}

	// Iterate targetRuleItem instances in token
	// groups of five (5):
	//
	// 1 - Open Paren "("
	// 2 - Keyword
	// 3 - Operator
	// 4 - Value(s)
	// 5 - Closing Paren ")"
	for len(tkz) >= 5 && err == nil {
		if tkz[0].Type == trParenOpen &&
			tkz[1].Type == trKeyword &&
			tkz[2].Type == trOperator {
			var ex []any
			var i int
			for i = 3; i < len(tkz); i++ {
				if typ := tkz[i].Type; typ != trParenClose {
					if typ == trValue {
						ex = append(ex, tkz[i].Value)
					}
				} else {
					break
				}
			}
			var item ACIv3TargetRuleItem
			if item, err = newACIv3TargetRuleItem(tkz[1].Value, tkz[2].Value, ex...); err == nil {
				tkz = tkz[i+1:]
				r.Push(item)
			}
		}
	}

	return err
}

func processACIv3TargetRuleItem(tkz []aCITargetRuleToken) (r ACIv3TargetRuleItem, err error) {
	r = badACIv3TargetRuleItem
	if l := len(tkz); l < 5 {
		err = errorTxt("unexpected number of tokens; want 5 or more, got " + itoa(l))
		return
	}

	if tkz[0].Value != "(" || tkz[4].Value != ")" {
		err = errorTxt("Missing targetRuleItem parenthesis")
		return
	}

	kw := matchTKW(tkz[1].Value)
	if kw == 0x0 {
		err = badACIv3KWErr
		return
	}

	op := matchACIv3Cop(tkz[2].Value)
	if !(0 < op && op <= 2) {
		err = badACIv3CopErr
		return
	}

	// TODO: check types per keyword
	if r, err = newACIv3TargetRuleItem(kw, op, tkz[3].Value); err == nil {
		err = r.Valid()
	}

	return
}

func tokenizeACIv3TargetRule(input string) (tkz []aCITargetRuleToken, err error) {
	i := 0
	length := len(input)
	if length == 0 {
		err = badACIv3TRErr
		return
	}

	for i < length && err == nil {
		// Skip any whitespace (spaces, tabs, etc.). These are insignificant.
		for i < length && isSpace(rune(input[i])) {
			i++
		}

		ch := input[i]
		switch ch {
		case '(':
			tkz = append(tkz, aCITargetRuleToken{Type: trParenOpen, Value: "("})
			i++
		case ')':
			tkz = append(tkz, aCITargetRuleToken{Type: trParenClose, Value: ")"})
			i++
		case '=':
			tkz = append(tkz, aCITargetRuleToken{Type: trOperator, Value: "="})
			i++
		case '!':
			// For "!=" operator, the '!' must be immediately followed by '='.
			if i+1 < length && input[i+1] == '=' {
				tkz = append(tkz, aCITargetRuleToken{Type: trOperator, Value: "!="})
				i += 2
			} else {
				err = errorTxt("targetRule unexpected token '!' without '=' following")
			}
		case '"':
			// Parse a quoted string literal.
			tkz, i, err = tokenizeTargetRuleQuotedValue(i, length, input, tkz)
		case '|':
			// Process the keyword, which is never quoted, and purely lower alphabetical
			tkz, i, err = tokenizeACIv3TargetRuleMultival(i, length, input, tkz)
		default:
			// Process the keyword, which is never quoted, and purely lower alphabetical
			tkz, i, err = tokenizeACIv3TargetRuleKeyword(ch, i, length, input, tkz)
		}
	}

	return tkz, nil
}

func tokenizeACIv3TargetRuleMultival(i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	var err error
	if i+1 < l && input[i+1] == '|' {
		tkz = append(tkz, aCITargetRuleToken{Type: trDelim, Value: "||"})
		i += 2
	} else {
		err = errorTxt("targetRule expected '||' for value delimiter, got single '|'")
	}

	return tkz, i, err
}

func tokenizeACIv3TargetRuleKeyword(ch byte, i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	// Process the key, which is never quoted, and purely alphabetical
	var err error
	if isAlpha(rune(ch)) {
		start := i
		for i < l && isAlpha(rune(input[i])) {
			i++
		}
		identifier := input[start:i]
		tkz = append(tkz, aCITargetRuleToken{Type: trKeyword, Value: identifier})
	} else {
		err = errorTxt("targetRule unexpected character '" + string(ch) + "' at position " + itoa(i))
	}

	return tkz, i, err
}

func tokenizeTargetRuleQuotedValue(i, l int, input string, tkz []aCITargetRuleToken) ([]aCITargetRuleToken, int, error) {
	i++ // skip the opening quote
	sb := newStrBuilder()
	var err error
	for i < l {
		if input[i] == '"' {
			// Found the closing quote.
			i++ // consume the closing quote and break.
			break
		}
		sb.WriteByte(input[i])
		i++
	}
	tkz = append(tkz, aCITargetRuleToken{Type: trValue, Value: sb.String()})
	return tkz, i, err
}

func processACIv3BindRule(tokens []aCIBindRuleToken, pos *int) (ACIv3BindRule, error) {
	if *pos >= len(tokens) {
		return nil, errorTxt("unexpected end of tokens")
	}

	// If a parenthesized group is encountered, defer to the group parser.
	if tokens[*pos].Type == brParenOpen {
		return parseACIv3BindRuleGroup(tokens, pos)
	}

	// Otherwise, join all adjacent value tokens.
	var parts []string
	for *pos < len(tokens) && tokens[*pos].Type == brValue {
		parts = append(parts, tokens[*pos].Value)
		*pos++
	}
	joined := join(parts, " ")
	operators := []string{"<=", ">=", "!=", "=", "<", ">"}
	for _, op := range operators {
		if idx := stridx(joined, op); idx != -1 {
			bkw := matchBKW(trimS(joined[:idx]))
			cop := matchACIv3Cop(trimS(joined[idx : idx+len(op)]))
			valueStr := trimS(joined[idx+len(op):])
			if val, err := assertBindValueByKeyword(bkw, valueStr); err == nil {
				rule := newACIv3BindRuleItem(bkw, cop, val)
				return rule.SetParen(false), rule.Valid()
			} else {
				return nil, err
			}
		}
	}
	return badACIv3BindRule, nil
}

func assertBindValueByKeyword(bkw ACIv3BindKeyword, raw ...any) (value any, err error) {
	if len(raw) == 0 {
		err = badACIv3BRExprErr
		return
	}

	switch bkw {
	case ACIv3BindUDN, ACIv3BindGDN, ACIv3BindRDN:
		arg := append([]any{bkw}, raw...)
		value, err = marshalACIv3BindDistinguishedName(arg...)
	case ACIv3BindUAT, ACIv3BindGAT:
		value, err = assertBindAT(bkw, raw...)
	case ACIv3BindDNS:
		value, err = marshalACIv3FQDN(raw...)
	case ACIv3BindDoW:
		value, err = marshalACIv3DayOfWeek(raw...)
	case ACIv3BindToD:
		value, err = marshalACIv3TimeOfDay(raw...)
	case ACIv3BindSSF:
		value, err = marshalACIv3SecurityStrengthFactor(raw...)
	case ACIv3BindAM:
		value, err = marshalACIv3AuthenticationMethod(raw...)
	case ACIv3BindIP:
		value, err = marshalACIv3IPAddress(raw...)
	}

	if err == nil && value == nil {
		err = nilInstanceErr
	}

	return
}

func assertBindAT(bkw ACIv3BindKeyword, raw ...any) (value any, err error) {
	switch tv := raw[0].(type) {
	case string:
		if cntns(tv, `[`) {
			value, err = marshalACIv3Inheritance(raw...)
		} else {
			value, err = marshalACIv3AttributeBindTypeOrValue(append([]any{bkw}, raw...)...)
		}
	case ACIv3Inheritance:
		value = tv
		err = tv.Valid()
	case ACIv3AttributeBindTypeOrValue:
		value = tv
		err = tv.Valid()
	}

	return
}

func assertTargetValueByKeyword(tkw ACIv3TargetKeyword, raw ...any) (value any, err error) {
	if len(raw) == 0 {
		err = nilInputErr
		return
	}

	switch tkw {
	case ACIv3Target, ACIv3TargetTo, ACIv3TargetFrom:
		arg := append([]any{tkw}, raw...)
		value, err = marshalACIv3TargetDistinguishedName(arg...)
	case ACIv3TargetCtrl, ACIv3TargetExtOp:
		arg := append([]any{tkw}, raw...)
		value, err = marshalACIv3ObjectIdentifier(tkw, arg...)
	case ACIv3TargetAttr:
		value, err = assertTargetRuleAttribute(raw...)
	case ACIv3TargetAttrFilters:
		switch raw[0].(type) {
		case ACIv3AttributeFilterOperation:
			value, err = marshalACIv3AttributeFilterOperation(raw...)
		case ACIv3AttributeFilterOperationItem:
			value, err = marshalACIv3AttributeFilterOperationItem(raw...)
		}
	case ACIv3TargetFilter:
		if len(raw) > 0 {
			value, err = marshalFilter(raw[0])
		}
	case ACIv3TargetScope:
		value, err = marshalACIv3SearchScope(raw...)
	}

	if err == nil && value == nil {
		err = nilInstanceErr
	}

	return
}

func assertTargetRuleAttribute(raw ...any) (value any, err error) {
	switch tv := raw[0].(type) {
	case string:
		if cntns(tv, `#`) {
			value, err = marshalACIv3AttributeBindTypeOrValue(raw...)
		} else {
			value, err = marshalACIv3Attribute(raw...)
		}
	case ACIv3Attribute:
		value = tv
		err = tv.Valid()
	case ACIv3AttributeBindTypeOrValue:
		value = tv
		err = tv.Valid()
	}

	return
}

func parseACIv3BindRuleGroup(tokens []aCIBindRuleToken, pos *int) (ACIv3BindRule, error) {
	if tokens[*pos].Type != brParenOpen {
		return nil, errorTxt("expected '(' but got " + tokens[*pos].Value)
	}
	*pos++ // skip '('

	// Process the first operand.
	operand, err := processACIv3BindRule(tokens, pos)
	if err != nil {
		return nil, err
	}
	operands := []ACIv3BindRule{operand}
	var operators []aCIBindRuleTokenType

	// Parse remaining tokens until a closing parenthesis is reached.
	for *pos < len(tokens) && tokens[*pos].Type != brParenClose {
		if !tokens[*pos].Type.isBooleanOperator() {
			return nil, errorTxt("expected boolean operator but got " + tokens[*pos].Value)
		}
		operators = append(operators, tokens[*pos].Type)
		*pos++
		nextOperand, err := processACIv3BindRule(tokens, pos)
		if err != nil {
			return nil, err
		}
		operands = append(operands, nextOperand)
	}
	if *pos >= len(tokens) || tokens[*pos].Type != brParenClose {
		return nil, errorTxt("expected closing parenthesis")
	}
	*pos++ // skip closing parenthesis

	// Decide which kind of boolean grouping to use.
	if len(operators) == 0 {
		return operands[0].SetParen(true), nil
	}

	var allAnd, allOr bool
	var r ACIv3BindRule

	if allAnd, allOr, err = getAndOrBool(operators); allOr {
		r = ACIv3BindRuleOr{&aCIBindRuleSlice{slice: operands, paren: true}}
	} else if allAnd {
		// In an AND group, any brNot wraps the corresponding operand.
		var newOperands []ACIv3BindRule
		newOperands = append(newOperands, operands[0])
		for idx, op := range operators {
			if op == brNot {
				not := ACIv3BindRuleNot{newACIv3BindRuleNot(operands[idx+1])}
				newOperands = append(newOperands, not)
			} else {
				newOperands = append(newOperands, operands[idx+1])
			}
		}
		r = ACIv3BindRuleAnd{&aCIBindRuleSlice{slice: newOperands, paren: true}}
	}

	return r, err
}

func parseACIv3BindRuleExpression(tokens []aCIBindRuleToken) (ACIv3BindRule, error) {
	pos := 0
	// We require at least three (3) tokens
	if len(tokens) < 3 {
		return nil, errorTxt("incomplete bind rule expression")
	}
	left, err := processACIv3BindRule(tokens, &pos)
	if err != nil {
		return nil, err
	}
	operands := []ACIv3BindRule{left}
	var operators []aCIBindRuleTokenType

	// Process top-level operator-operand pairs.
	for pos < len(tokens) {
		if !tokens[pos].Type.isBooleanOperator() {
			return nil, errorTxt("unexpected token encountered at top level: " + tokens[pos].Value)
		}
		operators = append(operators, tokens[pos].Type)
		pos++
		nextOperand, err := processACIv3BindRule(tokens, &pos)
		if err != nil {
			return nil, err
		}
		operands = append(operands, nextOperand)
	}

	var allAnd, allOr bool
	var r ACIv3BindRule

	if allAnd, allOr, err = getAndOrBool(operators); allOr {
		r = ACIv3BindRuleOr{&aCIBindRuleSlice{slice: operands}}
	} else if allAnd {
		// In an AND group, any brNot wraps the corresponding operand.
		var newOperands []ACIv3BindRule
		newOperands = append(newOperands, operands[0])
		for idx, op := range operators {
			if op == brNot {
				not := ACIv3BindRuleNot{newACIv3BindRuleNot(operands[idx+1])}
				newOperands = append(newOperands, not)
			} else {
				newOperands = append(newOperands, operands[idx+1])
			}
		}
		r = ACIv3BindRuleAnd{&aCIBindRuleSlice{slice: newOperands}}
	}

	return r, err
}

func getAndOrBool(operators []aCIBindRuleTokenType) (allAnd, allOr bool, err error) {
	allOr, allAnd = true, true
	for _, op := range operators {
		if op != brOr {
			allOr = false
		}
		if op != brAnd && op != brNot {
			allAnd = false
		}
	}

	if !allAnd && !allOr {
		err = errorTxt("mixed operators at top level are not supported")
	}

	return
}

func parseACIv3BindRuleTokens(tokens []aCIBindRuleToken) (rule ACIv3BindRule, err error) {
	pos := 0
	rule, err = processACIv3BindRule(tokens, &pos)
	if pos != len(tokens) {
		err = errorTxt("extra tokens remain after parsing")
	}

	return
}

func newDoW() ACIv3DayOfWeek {
	return ACIv3DayOfWeek(shifty.New(shifty.Uint8))
}

func newLvls() *aCILevels {
	l := aCILevels(shifty.New(shifty.Uint16))
	return &l
}

func newRights() *aCIRights {
	r := aCIRights(shifty.New(shifty.Uint16))
	return &r
}

func (r ACIv3DayOfWeek) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

func (r aCILevels) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

func (r aCIRights) cast() shifty.BitValue {
	return shifty.BitValue(r)
}

type (
	// [ACIv3DayOfWeek] is a type alias of [shifty.BitValue], and is used
	// to construct a dayofweek [ACIv3BindRule].
	ACIv3DayOfWeek shifty.BitValue // 8-bit

	// rights is a private type alias of shifty.BitValue, and is
	// used in the construction of an instance of [Permission].
	aCIRights shifty.BitValue // 16-bit

	// levels is a private type alias of shifty.BitValue, and is
	// used in the construction of an inheritance-based userattr
	// or groupattr ACIv3BindRule by embedding.
	aCILevels shifty.BitValue // 16-bit

)

/*
ACIv3Inheritance describes an inherited [ACIv3BindRule] syntax, allowing access control over child entry enumeration below the specified parent.
*/
type ACIv3Inheritance struct {
	ACIv3AttributeBindTypeOrValue
	*aCILevels
}

/*
Inheritance creates a new instance of [Inheritance] bearing the provided [ACIv3AttributeBindTypeOrValue] instance, as well as zero (0) or more [ACIv3Level] instances for shifting.
*/
func (r NetscapeACIv3) Inheritance(x ...any) (ACIv3Inheritance, error) {
	return marshalACIv3Inheritance(x...)
}

func marshalACIv3Inheritance(x ...any) (r ACIv3Inheritance, err error) {
	switch len(x) {
	case 0:
		err = nilInstanceErr
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = r.parse(tv)
		case ACIv3Inheritance:
			if err = tv.Valid(); err == nil {
				r = tv
			}
		default:
			err = badACIv3InhErr
		}
	default:
		switch tv := x[0].(type) {
		case string:
			var atb ACIv3AttributeBindTypeOrValue
			atb, err = marshalACIv3AttributeBindTypeOrValue(tv)
			if err == nil {
				r.ACIv3AttributeBindTypeOrValue = atb
				r.aCILevels = newLvls()
				r.Shift(x[1:]...)
			}
		case ACIv3AttributeBindTypeOrValue:
			if err = tv.Valid(); err == nil {
				r.ACIv3AttributeBindTypeOrValue = tv
				r.aCILevels = newLvls()
				r.Shift(x[1:]...)
			}
		default:
			err = badACIv3InhErr
		}
	}

	return
}

/*
ACIv3InheritanceLevel describes a discrete numerical abstract of a single subordinate level. [ACIv3InheritanceLevel] describes any single [ACIv3InheritanceLevel] definition. [ACIv3InheritanceLevel] constants are intended for "storage" within an instance of [ACIv3Inheritance].

Valid [ACIv3InheritanceLevel] constants are level zero (0) through level nine (9), though the supported range will vary across directory implementations.
*/
type ACIv3InheritanceLevel uint16

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r ACIv3Inheritance) IsZero() bool {
	return r.ACIv3AttributeBindTypeOrValue.IsZero() && r.aCILevels == nil
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r ACIv3Inheritance) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.ACIv3AttributeBindTypeOrValue.IsZero() || r.Len() > 10 {
		err = badACIv3InheritanceLevelErr
	}

	return
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3Inheritance) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindUAT] or [ACIv3BindGAT] [ACIv3BindKeyword] contexts.
*/
func (r ACIv3Inheritance) Eq() (b ACIv3BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(r.ACIv3AttributeBindTypeOrValue.
			ACIv3BindKeyword, ACIv3Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindUAT] or [ACIv3BindGAT] [ACIv3BindKeyword] contexts.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3Inheritance) Ne() (b ACIv3BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(r.ACIv3AttributeBindTypeOrValue.
			ACIv3BindKeyword, ACIv3Ne, r)
	}
	return
}

/*
parseACIv3Inheritance is a private function that reads the input string (inh) and attempts to marshal its contents into an instance of Inheritance (I), which is returned alongside an error (err).

This function is called during the bind rule parsing phase if and when an inheritance-related userattr/groupattr rule is encountered.
*/
func (r *ACIv3Inheritance) parse(inh string) (err error) {
	// Bail out immediately if the prefix is
	// non conformant.
	if !hasPfx(lc(inh), `parent[`) {
		err = badACIv3InhErr
		return
	}

	// chop off the 'parent[' prefix; we don't need
	// to preserve it following the presence check.
	raw := inh[7:]

	// Grab the sequence of level identifiers up to
	// and NOT including the right (closing) bracket.
	// The integer index (idx) marks the boundary of
	// the identifier sequence.
	idx := idxr(raw, ']')
	if idx == -1 {
		err = badACIv3InhErr
		return
	}

	// make sure the dot delimiter
	// comes immediately after the
	// closing square bracket.
	if raw[idx+1] != '.' {
		err = badACIv3InhErr
		return
	}

	// Initialize our return instance, as we're about
	// to begin storing things in it.
	r.aCILevels = newLvls()

	// Iterate the split sequence of level identifiers.
	// Also, obliterate any ASCII #32 (SPACE) chars
	// (e.g.: ', ' -> ',').
	X := split(repAll(raw[:idx], ` `, ``), `,`)
	for _, s := range X {
		r.Shift(s)
	}

	// Bail if nothing was found (do not fall
	// back to default when parsing).
	if r.aCILevels.cast().Int() == 0 {
		// bogus or unsupported identifiers?
		err = missingACIv3LvlsErr
		return
	}

	// Call our ACIv3AttributeBindTypeOrValue parser
	// and marshal a new instance to finish up.
	// At this phase, we begin value parsing
	// one (1) character after the identifier
	// boundary (see above).
	var abv ACIv3AttributeBindTypeOrValue

	if abv, err = parseATBTV(raw[idx+2:]); err == nil {
		r.ACIv3AttributeBindTypeOrValue = abv
	}

	return
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [ACIv3InheritanceLevel] instances currently being expressed.

For example, if the receiver instance has its [ACIv3Level1] and [ACIv3Level5] bits enabled, this would represent an abstract length of two (2).
*/
func (r ACIv3Inheritance) Len() int {
	var D int
	for i := 0; i < aCILevelBitIter; i++ {
		if d := ACIv3InheritanceLevel(1 << i); r.Positive(d) {
			D++
		}
	}

	return D
}

/*
Keyword returns the [ACIv3BindKeyword] associated with the receiver instance enveloped as a [ACIv3Keyword]. In the context of this type instance, the [ACIv3BindKeyword] returned will be either [ACIv3BindUAT] or [ACIv3BindGAT].
*/
func (r ACIv3Inheritance) Keyword() (kw ACIv3Keyword) {
	if err := r.Valid(); err != nil {
		return nil
	}

	k := r.ACIv3AttributeBindTypeOrValue.ACIv3BindKeyword
	switch k {
	case ACIv3BindGAT, ACIv3BindUAT:
		kw = k
	}

	return
}

/*
String returns the string name value for receiver instance.

The return value(s) are enclosed within square-brackets, followed by comma delimitation and are prefixed with "parent" before being returned.
*/
func (r ACIv3Inheritance) String() (s string) {
	s = badACIv3InhStr
	if err := r.Valid(); err == nil {
		lvls := r.aCILevels.string()
		s = "parent[" + lvls + "]." + r.ACIv3AttributeBindTypeOrValue.String()
	}
	return
}

/*
String is a string method that returns the string representation of the receiver instance.
*/
func (r aCILevels) string() string {
	var levels []string
	if r.cast().Int() > 0 {
		for i := 0; i < aCILevelBitIter; i++ {
			if shift := ACIv3InheritanceLevel(1 << i); r.cast().Positive(shift) {
				levels = append(levels, shift.String())
			}
		}
	}

	return join(levels, `,`)
}

/*
String returns a single string name value for receiver instance of [ACIv3Level].
*/
func (r ACIv3InheritanceLevel) String() (lvl string) {
	for k, v := range aCILevelNumbers {
		if r == v {
			lvl = k
			break
		}
	}

	return
}

/*
Shift wraps the [shifty.BitValue.Shift] method.
*/
func (r ACIv3Inheritance) Shift(x ...any) ACIv3Inheritance {
	if r.aCILevels == nil {
		r.aCILevels = newLvls()
	}

	for i := 0; i < len(x); i++ {
		var lvl ACIv3InheritanceLevel
		switch tv := x[i].(type) {
		case ACIv3InheritanceLevel:
			lvl = tv
		case int:
			lvl = assertIntInheritance(tv)
		case string:
			lvl = assertStrInheritance(tv)
		}
		r.aCILevels.cast().Shift(lvl)
	}

	return r
}

/*
assertStrInheritance returns the appropriate [ACIv3Level] instance logically associated with the string value (x) input by the user. Valid levels are zero (0) through four (4), else invalidACIv3InheritanceLevel is returned.
*/
func assertStrInheritance(x string) (lvl ACIv3InheritanceLevel) {
	for k, v := range aCILevelNumbers {
		if x == k {
			lvl = v
			break
		}
	}

	return
}

/*
assertIntInheritance returns the appropriate Level instance logically associated with the integer value (x) input by the user. Valid levels are zero (0) through four (4), else invalidACIv3InheritanceLevel is returned.
*/
func assertIntInheritance(x int) (lvl ACIv3InheritanceLevel) {
	if L, found := aCILevelMap[x]; found {
		lvl = L
	}

	return
}

/*
Positive wraps the [shifty.BitValue.Positive] method.
*/
func (r ACIv3Inheritance) Positive(x any) (posi bool) {
	if !r.IsZero() {
		var lvl ACIv3InheritanceLevel

		switch tv := x.(type) {
		case ACIv3InheritanceLevel:
			lvl = tv
		case int:
			lvl = assertIntInheritance(tv)
		case string:
			lvl = assertStrInheritance(tv)
		}
		posi = r.aCILevels.cast().Positive(lvl)
	}

	return
}

/*
Unshift wraps the [shifty.BitValue.Unshift] method.
*/
func (r ACIv3Inheritance) Unshift(x ...any) ACIv3Inheritance {
	if !r.IsZero() {
		for i := 0; i < len(x); i++ {
			var lvl ACIv3InheritanceLevel
			switch tv := x[i].(type) {
			case ACIv3InheritanceLevel:
				lvl = tv
			case int:
				lvl = assertIntInheritance(tv)
			case string:
				lvl = assertStrInheritance(tv)
			}
			r.aCILevels.cast().Unshift(lvl)
		}
	}

	return r
}

//// DN

type ACIv3BindDistinguishedName struct {
	ACIv3BindKeyword
	*aCIDistinguishedName
}

type ACIv3TargetDistinguishedName struct {
	ACIv3TargetKeyword
	*aCIDistinguishedName
}

type aCIDistinguishedName struct {
	slice []string // use string instead of proper DN type, as ACIv3 allows wildcard DNs
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3BindDistinguishedName) IsZero() bool {
	return r.aCIDistinguishedName == nil
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3TargetDistinguishedName) IsZero() bool {
	return r.aCIDistinguishedName == nil
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3BindDistinguishedName) Len() int {
	var l int
	if !r.IsZero() {
		l = r.aCIDistinguishedName.len()
	}

	return l
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3TargetDistinguishedName) Len() int {
	var l int
	if !r.IsZero() {
		l = r.aCIDistinguishedName.len()
	}

	return l
}

func (r *aCIDistinguishedName) len() int {
	var l int
	if r != nil {
		l = len(r.slice)
	}

	return l
}

/*
Push appends zero (0) or more values to the receiver. Each value
MUST be a [DistinguishedName], or its string equivalent.
*/
func (r ACIv3BindDistinguishedName) Push(x ...any) ACIv3BindDistinguishedName {
	if !r.IsZero() {
		_ = r.aCIDistinguishedName.push(x...)
	}

	return r
}

/*
Eq returns an instance of [ACIv3BindRuleItem], enveloped as an [ACIv3BindRule],
bearing the associated [ACIv3BindKeyword] in equality form.
*/
func (r ACIv3BindDistinguishedName) Eq() ACIv3BindRule {
	var br ACIv3BindRule = badACIv3BindRule
	if r.Len() > 0 {
		br = newACIv3BindRuleItem(r.ACIv3BindKeyword, ACIv3Eq, r)
	}

	return br
}

/*
Ne returns an instance of [ACIv3BindRuleItem], enveloped as an [ACIv3BindRule],
bearing the associated [ACIv3BindKeyword] in negated equality form.

Negated equalient [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3BindDistinguishedName) Ne() ACIv3BindRule {
	var br ACIv3BindRule = badACIv3BindRule
	if r.Len() > 0 {
		br = newACIv3BindRuleItem(r.ACIv3BindKeyword, ACIv3Ne, r)
	}

	return br
}

/*
Push appends zero (0) or more values to the receiver. Each value
MUST be a [DistinguishedName], or its string equivalent.
*/
func (r ACIv3TargetDistinguishedName) Push(x ...any) ACIv3TargetDistinguishedName {
	if !r.IsZero() {
		_ = r.aCIDistinguishedName.push(x...)
	}

	return r
}

/*
Eq returns an instance of [ACIv3TargetRuleItem] bearing the associated
[ACIv3TargetKeyword] in equality form.
*/
func (r ACIv3TargetDistinguishedName) Eq() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	if r.Len() > 0 {
		_tr, err := newACIv3TargetRuleItem(r.ACIv3TargetKeyword, ACIv3Eq, r)
		if err == nil {
			tr = _tr
		}
	}

	return tr
}

/*
Ne returns an instance of [ACIv3BindRuleItem], enveloped as an [ACIv3BindRule],
bearing the associated [ACIv3BindKeyword] in equality form.

Negated equalient [ACIv3TargetRuleItem] instances should be used with caution.
*/
func (r ACIv3TargetDistinguishedName) Ne() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	if r.Len() > 0 {
		_tr, err := newACIv3TargetRuleItem(r.ACIv3TargetKeyword, ACIv3Ne, r)
		if err == nil {
			tr = _tr
		}
	}

	return tr
}

func isACIv3SpecialDN(x string) bool {
	return strInSlice(lc(x), []string{
		"ldap:///anyone",
		"ldap:///all",
		"ldap:///self",
		"ldap:///parent",
	})
}

func (r *aCIDistinguishedName) push(x ...any) (err error) {
	for i := 0; i < len(x) && err == nil; i++ {
		switch tv := x[i].(type) {
		case string:
			if len(split(tv, `=`)) >= 2 || isACIv3SpecialDN(tv) {
				if !hasPfx(tv, "ldap:///") {
					tv = "ldap:///" + tv
				}
				if !r.contains(tv) {
					r.slice = append(r.slice, tv)
				}
			} else {
				err = badACIv3PushErr
			}
		case DistinguishedName:
			dn := tv.String()
			if _, err = marshalDistinguishedName(dn); err == nil && !r.contains(dn) {
				r.slice = append(r.slice, "ldap:///"+dn)
			}
		case ACIv3BindDistinguishedName:
			// In case the user wants to "merge" multiple DNs into one
			// single statement ...
			for i := 0; i < len(tv.aCIDistinguishedName.slice); i++ {
				r.push(tv.aCIDistinguishedName.slice[i])
			}
		case ACIv3TargetDistinguishedName:
			// same
			for i := 0; i < len(tv.aCIDistinguishedName.slice); i++ {
				r.push(tv.aCIDistinguishedName.slice[i])
			}
		}
	}

	return
}

func (r aCIDistinguishedName) string(mvq, pad bool) string {
	var s string
	if L := r.len(); L > 0 {
		var _s []string
		if mvq {
			for i := 0; i < L; i++ {
				_s = append(_s, `"`+r.slice[i]+`"`)
			}
		} else {
			for i := 0; i < L; i++ {
				_s = append(_s, r.slice[i])
			}
		}

		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return s
}

/*
Index returns the Nth string present within the receiver instance.
*/
func (r ACIv3BindDistinguishedName) Index(idx int) string {
	var s string
	if !r.IsZero() {
		s = r.aCIDistinguishedName.index(idx)
	}

	return s
}

/*
Index returns the Nth string present within the receiver instance.
*/
func (r ACIv3TargetDistinguishedName) Index(idx int) string {
	var s string
	if !r.IsZero() {
		s = r.aCIDistinguishedName.index(idx)
	}

	return s
}

func (r aCIDistinguishedName) index(idx int) string {
	var dn string

	if 0 <= idx && idx < r.len() {
		dn = r.slice[idx]
	}

	return dn
}

/*
Contains returns a Boolean value indicative of a match between x
and a slice value in the receiver instance.

x MUST be a proper [DistinguishedName] instance, or its string
equivalent.
*/
func (r ACIv3BindDistinguishedName) Contains(x any) bool {
	var c bool
	if !r.IsZero() {
		c = r.aCIDistinguishedName.contains(x)
	}

	return c
}

/*
Contains returns a Boolean value indicative of a match between x
and a slice value in the receiver instance.

x MUST be a proper [DistinguishedName] instance, or its string
equivalent.
*/
func (r ACIv3TargetDistinguishedName) Contains(x any) bool {
	var c bool
	if !r.IsZero() {
		c = r.aCIDistinguishedName.contains(x)
	}

	return c
}

func (r aCIDistinguishedName) contains(x any) bool {
	var term string
	switch tv := x.(type) {
	case string:
		term = tv
	case DistinguishedName:
		term = tv.String()
	}

	return strInSlice(term, r.slice)
}

//// ATTRS

/*
ACIv3AttributeBindTypeOrValue contains a statement of the following syntax:

	<AttributeName>#<BindType -OR- AttributeValue>

Instances of this type are used in certain [ACIv3BindRule] instances, particularly
those that involve user-attribute or group-attribute [ACIv3BindKeyword] instances.
*/
type ACIv3AttributeBindTypeOrValue struct {
	ACIv3BindKeyword // Constraint: ACIv3BindUAT or ACIv3BindGAT keywords only!
	*atbtv           // Embedded PTR
}

/*
atbtv is the embedded (BY POINTER!) type found within instances of ACIv3AttributeBindTypeOrValue.

Slices are as follows:
  - 0: <atoid> (ACIv3Attribute)
  - 1: <atv>   (ACIv3BindType -OR- AttributeValue)
*/
type atbtv [2]any

/*
IsZero returns a Boolean value indicative of whether the receiver is nil,
or unset.
*/
func (r ACIv3AttributeBindTypeOrValue) IsZero() bool {
	if r.atbtv == nil {
		return true
	}

	return r.ACIv3BindKeyword == 0x0
}

/*
AttributeBindTypeOrValue will return a new instance of [ACIv3AttributeBindTypeOrValue]. The
required [ACIv3BindKeyword] must be either [ACIv3BindUAT] or [ACIv3BindGAT]. The optional input values
(x), if provided, will be used to set the instance.
*/
func (r NetscapeACIv3) AttributeBindTypeOrValue(x ...any) (ACIv3AttributeBindTypeOrValue, error) {
	return marshalACIv3AttributeBindTypeOrValue(x...)
}

func marshalACIv3AttributeBindTypeOrValue(x ...any) (ACIv3AttributeBindTypeOrValue, error) {
	var a ACIv3AttributeBindTypeOrValue
	var err error

	if l := len(x); l > 0 {
		switch l {
		case 1:
			switch tv := x[0].(type) {
			case string:
				a, err = parseATBTV(tv)
			case ACIv3AttributeBindTypeOrValue:
				a = tv
			}
		case 2:
			var bkw ACIv3BindKeyword

			switch tv := x[0].(type) {
			case string:
				bkw = matchBKW(tv)
			case ACIv3BindKeyword:
				bkw = tv
			}

			switch tv := x[1].(type) {
			case string:
				a, err = parseATBTV(tv)
			case ACIv3AttributeBindTypeOrValue:
				a = tv
				a.ACIv3BindKeyword = bkw
			}
		default:
			a = aCIUserOrGroupAttr(x[0], x[1:]...)
		}
	}

	if err == nil {
		err = a.Valid()
	}

	return a, err
}

/*
aCIUserOrGroupAttr is a private package level function called by either the GroupAttr or UserAttr function. This function is the base initializer for the [ACIv3AttributeBindTypeOrValue] instance returned by said functions.
*/
func aCIUserOrGroupAttr(kw any, x ...any) (A ACIv3AttributeBindTypeOrValue) {
	var keyword ACIv3BindKeyword

	switch tv := kw.(type) {
	case string:
		keyword = matchBKW(kw)
	case ACIv3BindKeyword:
		if tv == ACIv3BindUAT || tv == ACIv3BindGAT {
			keyword = tv
		}
	}

	A = ACIv3AttributeBindTypeOrValue{
		keyword, new(atbtv),
	}

	if len(x) != 0 {
		A.atbtv.set(x...)
	}

	return
}

/*
Set assigns value(s) x to the receiver. The value(s) must be [ACIv3Attribute] and/or [AttributeValue] instances, created via the package-level [AT] and [AV] functions respectively.
*/
func (r ACIv3AttributeBindTypeOrValue) Set(x ...any) ACIv3AttributeBindTypeOrValue {
	if r.IsZero() {
		r.atbtv = new(atbtv)
	}
	r.atbtv.set(x...)
	return r
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To a [ACIv3BindUAT] or [ACIv3BindGAT] [ACIv3BindKeyword] context.
*/
func (r ACIv3AttributeBindTypeOrValue) Eq() (b ACIv3BindRule) {
	if !r.atbtv.isZero() {
		b = newACIv3BindRuleItem(r.ACIv3BindKeyword, ACIv3Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To a [ACIv3BindUAT] or [ACIv3BindGAT] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3AttributeBindTypeOrValue) Ne() (b ACIv3BindRule) {
	if !r.atbtv.isZero() {
		b = newACIv3BindRuleItem(r.ACIv3BindKeyword, ACIv3Ne, r)
	}
	return
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3AttributeBindTypeOrValue) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Keyword returns the [ACIv3BindKeyword] associated with the receiver instance, enveloped as a [ACIv3Keyword]. In the context of this type instance, the [ACIv3BindKeyword] returned will always be one (1) of [ACIv3BindUAT] or [ACIv3BindGAT].
*/
func (r ACIv3AttributeBindTypeOrValue) Keyword() ACIv3Keyword {
	var kw ACIv3Keyword = r.ACIv3BindKeyword
	switch kw {
	case ACIv3BindGAT:
		return ACIv3BindGAT
	}

	return ACIv3BindUAT
}

/*
isZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r *atbtv) isZero() bool {
	var z bool = true
	if r != nil {
		z = (r[0] == nil && r[1] == nil)
	}
	return z
}

/*
String returns the string representation of the receiver.
*/
func (r atbtv) String() (s string) {
	// Only one (1) of the following
	// vars will be used.
	var bt ACIv3BindType
	var av AttributeValue

	if r.isZero() {
		return
	}

	// Assert the attributeType value or bail out.
	if at, assert := r[0].(ACIv3Attribute); assert {
		// First see if the value is a BindType
		// keyword, as those are few and easily
		// identified.
		if bt, assert = r[1].(ACIv3BindType); !assert || bt == ACIv3BindType(0x0) {
			// If not a BindType kw, see if it
			// appears to be an AttributeValue.
			if av, assert = r[1].(AttributeValue); !assert || len(*av.string) == 0 {
				// value is neither an AttributeValue
				// nor BindType kw; bail out.
				return
			}

			// AttributeValue wins
			s = at.Index(0) + `#` + av.String()
			return
		}

		// BindType wins
		s = at.Index(0) + `#` + av.String()
	}

	return
}

/*
set assigns one (1) or more values (x) to the receiver. Only [ACIv3Attribute], [AttributeValue] and [ACIv3BindType] instances shall be assigned.

Note that if a string value is detected, it will be cast as the appropriate type and assigned to the appropriate slice in the receiver, but ONLY if said slice is nil.
*/
func (r *atbtv) set(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case ACIv3Attribute:
			if r[0] == nil {
				r[0] = tv
			}
		case AttributeValue, ACIv3BindType:
			r[1] = tv
		case string:
			if bt := matchBT(tv); bt != ACIv3BindType(0x0) {
				r[1] = bt
			} else {
				r[1] = AttributeValue{&tv}
			}
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AttributeBindTypeOrValue) String() string {
	var s string = badAVStr
	if r.atbtv != nil {
		if at, ok := r.atbtv[0].(ACIv3Attribute); ok {
			switch tv := r.atbtv[1].(type) {
			case AttributeValue:
				s = at.String() + `#` + (*tv.string)
			case ACIv3BindType:
				s = at.String() + `#` + tv.String()
			}
		}
	}
	return s
}

/*
Parse reads the input string (raw) in an attempt to marshal its contents into the receiver instance (r). An error is returned at the end of the process.

If no suitable [ACIv3BindKeyword] is provided (bkw), the default is [ACIv3BindUAT]. Valid options are [ACIv3BindUAT] and [ACIv3BindGAT].
*/
func (r *ACIv3AttributeBindTypeOrValue) parse(raw string, bkw ...any) (err error) {
	var _r ACIv3AttributeBindTypeOrValue
	if _r, err = parseATBTV(raw, bkw); err == nil {
		*r = _r
	}

	return
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r ACIv3AttributeBindTypeOrValue) Valid() (err error) {
	if !r.IsZero() {
		if r.atbtv[0] == nil || r.atbtv[1] == nil {
			err = badACIv3ATBTVErr
		}
	} else {
		err = nilInstanceErr
	}

	return
}

/*
parseATBTV parses the input string (x) in an attempt to marshal its contents
into an instance of [ACIv3AttributeBindTypeOrValue] (A), which is returned alongside
an error (err).

The optional ACIv3BindKeyword argument (bkw) allows the [ACIv3BindGAT] (groupattr) Bind
Rule keyword to be set, else the default of [ACIv3BindUAT] (userattr) will take
precedence.
*/
func parseATBTV(x string, bkw ...any) (A ACIv3AttributeBindTypeOrValue, err error) {
	// Obtain the index number for ASCII #35 (NUMBER SIGN).
	// If minus one (-1), input value x is totally bogus.
	idx := idxr(x, '#')
	if idx == -1 {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	} else if len(x[idx+1:]) == 0 {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	}

	// Set the groupattr keyword if requested, else
	// use the default of userattr.
	kw := assertATBTVBindKeyword(bkw...)

	at, _ := marshalACIv3Attribute(x[:idx])
	v := x[idx+1:]
	av := AttributeValue{&v}

	if at.Index(0) == badATStr {
		err = badACIv3AttributeBindTypeOrValueErr
		return
	}

	// If the remaining portion of the value is, in
	// fact, a known BIND TYPE keyword, pack it up
	// and ship it out.
	if bt := matchBT(x[idx+1:]); bt != ACIv3BindType(0x0) {
		A = aCIUserOrGroupAttr(kw, at, bt)
	} else {
		A = aCIUserOrGroupAttr(kw, at, av)
	}

	return
}

/*
ACIv3Attribute facilitates the storage of one (1) or more attribute OIDs, typically used in the
context of [ACIv3TargetRuleItem] attributes.
*/
type ACIv3Attribute struct {
	*aCIAttribute
}

type aCIAttribute struct {
	slice []string
	all   bool // "*"; mutex for len(slice)>0
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3Attribute) String() string {
	var s string = badATStr

	if !r.IsZero() {
		if r.aCIAttribute.all {
			s = `*`
		} else if r.Len() > 0 {
			s = join(r.aCIAttribute.slice, `||`)
		}
	}

	return s
}

/*
Eq initializes and returns a new [ACIv3TargetRuleItem] instance configured to express the evaluation of the receiver value as Equal-To a [ACIv3TargetAttr] [ACIv3TargetKeyword] context.
*/
func (r ACIv3Attribute) Eq() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		t, err := newACIv3TargetRuleItem(ACIv3TargetAttr, ACIv3Eq, r)
		if err == nil {
			tr = t
		}
	}

	return tr
}

/*
Ne initializes and returns a new [ACIv3TargetRuleItem] instance configured to express the evaluation of the receiver value as Not-Equal-To a [ACIv3TargetAttr] [ACIv3TargetKeyword] context.

Negated equality [ACIv3TargetRuleItem] instances should be used with caution.
*/
func (r ACIv3Attribute) Ne() (t ACIv3TargetRuleItem) {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		t, err := newACIv3TargetRuleItem(ACIv3TargetAttr, ACIv3Ne, r)
		if err == nil {
			tr = t
		}
	}

	return tr
}

/*
Kind performs no useful task, as the receiver instance has no concept of a keyword, which is the typical value source for Kind calls. This method exists solely to satisfy Go's interface signature requirements and will return a zero string if executed.
*/
func (r ACIv3Attribute) Kind() string { return `` }

/*
Keyword performs no useful task, as the receiver instance has no concept of a keyword. This method exists solely to satisfy Go's interface signature requirements and will return nil if executed.
*/
func (r ACIv3Attribute) Keyword() ACIv3Keyword { return nil }

/*
TRM returns an instance of [ACIv3TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3TargetRuleItem] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3TargetRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3TargetRuleItem] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3TargetRuleItem] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly initialized, populated and prepared for such activity.
*/
func (r ACIv3Attribute) TRM() ACIv3TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r ACIv3Attribute) Valid() (err error) {
	if r.IsZero() || r.Len() == 0 {
		err = nilInstanceErr
	}

	return
}

/*
Push appends zero (0) or more attributes to the receiver instance.
*/
func (r ACIv3Attribute) Push(x ...any) ACIv3Attribute {
	_ = r.push(x...)
	return r
}

func (r ACIv3Attribute) push(x ...any) (err error) {
	for i := 0; i < len(x) && !r.aCIAttribute.all && err == nil; i++ {
		switch tv := x[i].(type) {
		case *AttributeType:
			if tv.Valid() {
				r.aCIAttribute.slice = append(r.aCIAttribute.slice, tv.Identifier())
			} else {
				err = badACIv3AttributeErr
			}
		case []string:
			for j := 0; j < len(tv) && err == nil; j++ {
				err = r.push(trimS(tv[j]))
			}
		case string:
			if tv == `*` {
				r.aCIAttribute.slice = nil
				r.aCIAttribute.all = true
				break
			}
			sp := split(tv, `||`)
			for j := 0; j < len(sp) && err == nil; j++ {
				if at := trimS(sp[j]); isAttribute(at) {
					r.aCIAttribute.slice = append(r.aCIAttribute.slice, at)
				} else {
					err = badACIv3AttributeErr
				}
			}
		}
	}

	return err
}

func (r ACIv3Attribute) Len() int {
	var l int
	if r.aCIAttribute != nil {
		l = len(r.aCIAttribute.slice)
	}

	return l
}

func (r ACIv3Attribute) Index(idx int) string {
	var a string = badATStr
	if r.aCIAttribute != nil {
		if 0 <= idx && idx < r.Len() {
			a = r.aCIAttribute.slice[idx]
		}
	}

	return a
}

func (r ACIv3Attribute) IsZero() bool {
	return r.aCIAttribute == nil
}

/*
String returns the string representation of the underlying value within the receiver. The return value shall reflect an LDAP descriptor, such as `manager` or `cn`.
*/
func (r aCIAttribute) string(mvq, pad bool) (s string) {
	if r.all {
		s = `"*"`
	} else {
		var _s []string
		if mvq {
			for i := 0; i < len(r.slice); i++ {
				_s = append(_s, `"`+r.slice[i]+`"`)
			}
		} else {
			for i := 0; i < len(r.slice); i++ {
				_s = append(_s, r.slice[i])
			}
		}
		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return
}

/*
AttributeValue embeds a pointer value that reflects an attribute value.
*/
type AttributeValue struct {
	*string
}

/*
String returns the string representation of the underlying value within the receiver. The return value should be either an attributeType assertion value, or one (1) of the five (5) possible [ACIv3BindType] identifiers (e.g.: [ACIv3BindTypeUSERDN]).
*/
func (r AttributeValue) String() (s string) {
	s = badAVStr
	if r.string != nil {
		s = (*r.string)
	}

	return
}

//// TARGET

/*
ACIv3TargetRuleItem implements the base slice type for instances of [ACIv3TargetRuleItem].

Instances of this type shall contain a minimum of zero (0) and a maximum of nine (9)
valid [ACIv3TargetRuleItem] instances.

During the [ACIv3TargetRule.Push] (append) process, individual slices are checked for
uniqueness based on [ACIv3TargetKeyword] use. As such, no single [ACIv3TargetKeyword]
shall ever appear in more than one [ACIv3TargetRuleItem] instance found within instances
of this type.
*/
type ACIv3TargetRule struct {
	*aCITargetRule
}

type aCITargetRule struct {
	slice []ACIv3TargetRuleItem
}

func (r ACIv3TargetRule) IsZero() bool {
	return r.aCITargetRule == nil
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3TargetRule) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCITargetRule.slice)
	}

	return l
}

/*
Index returns the Nth instance of [ACIv3TargetRuleItem] present
within the receiver instance.
*/
func (r ACIv3TargetRule) Index(idx int) ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			tr = r.aCITargetRule.slice[idx]
		}
	}

	return tr
}

/*
Contains returns a Boolean value indicative of the presence an instance
of [ACIv3TargetRuleItem] bearing the specified [ACIv3TargetKeyword] within
the receiver instance.
*/
func (r ACIv3TargetRule) Contains(kw any) bool {
	var (
		c bool
		k ACIv3TargetKeyword = matchTKW(kw)
	)

	if !r.IsZero() {
		for i := 0; i < r.Len() && !c; i++ {
			c = r.aCITargetRule.slice[i].Keyword() == k
		}
	}

	return c
}

/*
Push appends zero (0) or more valid [ACIv3TargetRuleItem] instances to the
receiver instance.

If the specified [ACIv3TargetRuleItem] input instances bear [ACIv3TargetKeyword]s
already in use within the receiver instance, they are silently ignored.

Up to nine (9) possible [ACIv3TargetRuleItem] instances shall appear within
any instance of this type.
*/
func (r ACIv3TargetRule) Push(x ...any) ACIv3TargetRule {
	if !r.IsZero() {
		for i := 0; i < len(x) && r.Len() < 9; i++ {
			switch tv := x[i].(type) {
			case string:
				r.parse(tv)
			case ACIv3TargetRuleItem:
				if tv.Valid() == nil && !r.Contains(tv.Keyword()) {
					r.aCITargetRule.slice = append(r.aCITargetRule.slice, tv)
				}
			}

		}
	}

	return r
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r ACIv3TargetRule) Valid() (err error) {
	for i := 0; i < r.Len() && err == nil; i++ {
		err = r.Index(i).Valid()
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3TargetRule) String() string {
	var s string
	if r.Len() == 0 {
		// TargetRules are always OPTIONAL in any ACIv3, thus
		// we need not return an "invalid placeholder" value,
		// just a zero string.
		return ``
	}

	for i := 0; i < r.Len(); i++ {
		s += r.Index(i).String()
	}

	return s
}

/*
ACIv3TargetRuleItem implements the (optional) ACIv3 Target Rule slice value type.
Instances of this type are intended for storage within an instance of [ACIv3TargetRule].
*/
type ACIv3TargetRuleItem struct {
	*aCITargetRuleItem
}

type aCITargetRuleItem struct {
	Keyword    ACIv3TargetKeyword
	Operator   ACIv3Operator
	Expression any
	mvq        bool
	pad        bool
}

/*
ACIv3TargetRuleMethods contains one (1) or more instances of [ACIv3TargetRuleMethod], representing a particular [ACIv3TargetRuleItem] "builder" method for execution by the caller.

See the Operators method extended through all eligible types for further details.
*/
type ACIv3TargetRuleMethods struct {
	*aCITargetRuleFuncMap
}

/*
newTargetRuleMethods populates an instance of *targetRuleFuncMap, which is embedded within the return instance of ACIv3TargetRuleMethods.
*/
func newACIv3TargetRuleMethods(m aCITargetRuleFuncMap) ACIv3TargetRuleMethods {
	if len(m) == 0 {
		return ACIv3TargetRuleMethods{nil}
	}

	M := make(aCITargetRuleFuncMap, len(m))
	for k, v := range m {
		M[k] = v
	}

	return ACIv3TargetRuleMethods{&M}
}

/*
Index calls the input index (idx) within the internal structure of the receiver instance. If found, an instance of [ACIv3Operator] and its accompanying [ACIv3TargetRuleMethod] instance are returned.

Valid input index types are integer (int), [ACIv3Operator] constant or string identifier. In the case of a string identifier, valid values are as follows:

  - For ACIv3Eq (1): `=`, `Eq`, `Equal To`
  - For ACIv3Ne (2): `=`, `Ne`, `Not Equal To`
  - For ACIv3Lt (3): `=`, `Lt`, `Less Than`
  - For ACIv3Le (4): `=`, `Le`, `Less Than Or Equal`
  - For ACIv3Gt (5): `=`, `Gt`, `Greater Than`
  - For ACIv3Ge (6): `=`, `Ge`, `Greater Than Or Equal`

Case is not significant in the string matching process.

Please note that use of this method by way of integer or [ACIv3Operator] values utilizes fewer resources than a string lookup.

See the [ACIv3Operator.Context], [ACIv3Operator.String] and [ACIv3Operator.Description] methods for accessing the above string values easily.

If the index was not matched, an invalid [ACIv3Operator] is returned alongside a nil [ACIv3TargetRuleMethod]. This will also apply to situations in which the type instance which crafted the receiver is uninitialized, or is in an otherwise aberrant state.
*/
func (r ACIv3TargetRuleMethods) Index(idx any) (cop ACIv3Operator, meth ACIv3TargetRuleMethod) {
	if r.IsZero() {
		return
	}
	cop = invalidCop

	// perform a type switch upon the input
	// index type
	switch tv := idx.(type) {

	case ACIv3Operator:
		// cast cop as an int, and make recursive
		// call to this function.
		return r.Index(int(tv))

	case int:
		// there are only six (6) valid
		// operators, numbered one (1)
		// through six (6).
		if !(1 <= tv && tv <= 6) {
			return
		}

		var found bool
		if meth, found = (*r.aCITargetRuleFuncMap)[ACIv3Operator(tv)]; found {
			cop = ACIv3Operator(tv)
		}

	case string:
		cop, meth = rangeTargetRuleFuncMap(tv, r.aCITargetRuleFuncMap)
	}

	return
}

func rangeTargetRuleFuncMap(candidate string, fm *aCITargetRuleFuncMap) (cop ACIv3Operator, meth ACIv3TargetRuleMethod) {
	// iterate all map entries, and see if
	// input string value matches the value
	// returned by these three (3) methods:
	for k, v := range *fm {
		if strInSlice(candidate, []string{
			k.String(),      // e.g.: "="
			k.Context(),     // e.g.: "Eq"
			k.Description(), // e.g.: "Equal To"
		}) {
			cop = k
			meth = v
			break
		}
	}

	return
}

/*
Contains returns a Boolean value indicative of whether the specified [ACIv3Operator], which may be expressed as a string, int or native [ACIv3Operator], is allowed for use by the type instance that created the receiver instance. This method offers a convenient alternative to the use of the Index method combined with an assertion value (such as [ACIv3Eq], [ACIv3Ne], "=", "Greater Than", et al).

In other words, if one uses the [ACIv3TargetDistinguishedName]'s TRM method to create an instance of [ACIv3TargetRuleMethods], feeding [ACIv3Gt] (Greater Than) to this method shall return false, as no [ACIv3TargetRuleItem] context allows mathematical comparison.
*/
func (r ACIv3TargetRuleMethods) Contains(cop any) bool {
	c, _ := r.Index(cop)
	return c.Valid() == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3TargetRuleMethods) IsZero() bool {
	return r.aCITargetRuleFuncMap == nil
}

/*
Valid returns the first encountered error returned as a result of execution of the first available [ACIv3TargetRuleMethod] instance. This is useful in cases where a user wants to see if the desired instance(s) of [ACIv3TargetRuleMethod] will produce a usable result.
*/
func (r ACIv3TargetRuleMethods) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
		return
	}

	// ACIv3Eq is always available for all eligible
	// types, so let's use that unconditionally.
	// If any one method works, then all of them
	// will work.
	_, meth := r.Index(ACIv3Eq)
	err = meth().Valid()
	return
}

/*
Len returns the integer length of the receiver. Note that the return value will NEVER be less than zero (0) nor greater than six (6).
*/
func (r ACIv3TargetRuleMethods) Len() int {
	if r.IsZero() {
		return 0
	}

	return len((*r.aCITargetRuleFuncMap))
}

/*
ACIv3TargetRuleMethod is the closure signature for methods used to build new instances of [ACIv3TargetRuleItem].

The signature is qualified by the following methods extended through all eligible types defined in this package:

  - [ACIv3Eq]
  - [ACIv3Ne]

Note that [ACIv3TargetRuleItem] instances only support a very limited subset of these methods when compared to [ACIv3BindRule] instances. In fact, some [ACIv3TargetRuleItem] instances only support ONE such method: ACIv3Eq.
*/
type ACIv3TargetRuleMethod func() ACIv3TargetRuleItem

/*
aCITargetRuleFuncMap is a private type intended to be used within instances of ACIv3TargetRuleMethods.
*/
type aCITargetRuleFuncMap map[ACIv3Operator]ACIv3TargetRuleMethod

/*
Keyword returns the [ACIv3TargetKeyword] value currently set within the receiver instance.
*/
func (r ACIv3TargetRuleItem) Keyword() ACIv3TargetKeyword {
	var bkw ACIv3TargetKeyword = invalidACIv3TargetKeyword
	if &r != nil {
		bkw = r.aCITargetRuleItem.Keyword
	}

	return bkw
}

/*
Operator returns the [ACIv3Operator] value currently set within the receiver instance.
*/
func (r ACIv3TargetRuleItem) Operator() ACIv3Operator {
	var cop ACIv3Operator = invalidCop
	if &r != nil {
		cop = r.aCITargetRuleItem.Operator
	}

	return cop
}

/*
Expression returns the underlying expression value currently set within the receiver instance.
*/
func (r ACIv3TargetRuleItem) Expression() any {
	var val any
	if &r != nil {
		val = r.aCITargetRuleItem.Expression
	}

	return val
}

/*
TargetRuleItem initializes, populates and returns a new instance of [ACIv3TargetRuleItem].
*/
func (r NetscapeACIv3) TargetRuleItem(x ...any) (ACIv3TargetRuleItem, error) {
	var (
		tri ACIv3TargetRuleItem = ACIv3TargetRuleItem{&aCITargetRuleItem{}}
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			err = tri.parse(tv)
		case ACIv3TargetKeyword:
			if matchTKW(tv) != 0x0 {
				if len(x) == 3 {
					if _, ok := x[1].(ACIv3Operator); !ok {
						err = badACIv3TRErr
					} else {
						tri, err = newACIv3TargetRuleItem(x[0], x[1], x[2])
					}
				} else {
					err = badACIv3TRErr
				}
			} else {
				err = badACIv3TRErr
			}
		default:
			err = badACIv3TRErr
		}
	}

	return tri, err

}

func initACIv3TargetRuleItem() ACIv3TargetRuleItem {
	return ACIv3TargetRuleItem{&aCITargetRuleItem{
		Keyword:  invalidACIv3TargetKeyword,
		Operator: invalidCop,
	}}
}

func newACIv3TargetRuleItem(kw, op any, ex ...any) (tr ACIv3TargetRuleItem, err error) {
	tr = initACIv3TargetRuleItem().
		SetKeyword(kw).
		SetOperator(op)

	var value any
	if value, err = assertTargetValueByKeyword(tr.Keyword(), ex...); err == nil {
		tr.SetExpression(value)
	}

	if err == nil {
		err = tr.Valid()
	}

	return
}

/*
SetKeyword assigns [ACIv3Keyword] kw to the receiver instance.
*/
func (r ACIv3TargetRuleItem) SetKeyword(kw any) ACIv3TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}
	switch tv := kw.(type) {
	case string:
		r.aCITargetRuleItem.Keyword = matchTKW(tv)
	case ACIv3TargetKeyword:
		r.aCITargetRuleItem.Keyword = tv
	}

	return r
}

/*
SetOperator assigns [ACIv3Operator] op to the receiver
instance.
*/
func (r ACIv3TargetRuleItem) SetOperator(op any) ACIv3TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}

	// assert underlying comparison operator.
	var cop ACIv3Operator
	switch tv := op.(type) {
	case string:
		cop = matchACIv3Cop(tv)
	case ACIv3Operator:
		cop = tv
	}

	// For security reasons, only assign comparison
	// operator if it is Eq or Ne.
	if 0x0 < cop && cop <= 0x2 {
		r.aCITargetRuleItem.Operator = cop
	}

	return r
}

/*
SetExpression assigns value expr to the receiver instance.
*/
func (r ACIv3TargetRuleItem) SetExpression(expr any) ACIv3TargetRuleItem {
	if r.IsZero() {
		r.aCITargetRuleItem = initACIv3TargetRuleItem().aCITargetRuleItem
	}
	// TODO: constrain to specific types
	r.aCITargetRuleItem.Expression = expr

	return r
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3TargetRuleItem) IsZero() bool {
	return r.aCITargetRuleItem == nil
}

/*
Kind returns the string literal `targetRule`.
*/
func (r ACIv3TargetRuleItem) Kind() string {
	return `targetRule`
}

/*
Valid returns an error instance which, when non-nil, will indicate a logical
flaw, such a missing component of a [ACIv3TargetRuleItem] qualifier, or some
other issue.
*/
func (r ACIv3TargetRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = errorTxt("Invalid target rule item: is zero")
		return
	}

	for _, ok := range []bool{
		r.Keyword() != invalidACIv3TargetKeyword,
		r.Operator() != 0x0,

		// TODO:expand on this logic to limit validity
		// to high-level interface qualifiers only, or
		// raw string values.
		r.Expression() != nil,
	} {
		if !ok {
			err = errorTxt("Invalid target rule (ITEM): Missing bindRule keyword, operator or the expr value is bogus")
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3TargetRuleItem) String() (s string) {
	s = badACIv3TRStr
	if r.IsZero() {
		return s
	}

	// Try to coax a string out of the value.
	var raw string
	switch tv := r.Expression().(type) {
	case ACIv3TargetDistinguishedName:
		raw = tv.string(r.aCITargetRuleItem.mvq, r.aCITargetRuleItem.pad)
	case ACIv3ObjectIdentifier:
		raw = tv.string(r.aCITargetRuleItem.mvq, r.aCITargetRuleItem.pad)
	default:
		// For all other types, as a last resort, see
		// if the instance has its own Stringer, and
		// (if so) use it.
		if meth := getStringer(tv); meth != nil {
			raw = meth()
		} else {
			return s
		}
	}

	if !(hasPfx(raw, `"`) && hasSfx(raw, `"`)) {
		raw = `"` + raw + `"`
	}

	var pad string
	if r.pad {
		pad = ` `
	}

	s = `(` + pad + r.Keyword().String() + pad +
		r.Operator().String() + pad + raw + pad + `)`

	return
}

func (r *ACIv3TargetRuleItem) parse(x string) (err error) {
	var tkz []aCITargetRuleToken
	if tkz, err = tokenizeACIv3TargetRule(x); err == nil {
		*r, err = processACIv3TargetRuleItem(tkz)
	}

	return err
}

//// RIGHTS

/*
ACIv3Right contains the specific bit value of a single user privilege. Constants of this type are intended for submission to the [ACIv3Permission.Shift], [ACIv3Permission.Unshift] and [ACIv3Permission.Positive] methods.
*/
type ACIv3Right uint16

/*
ACIv3Permission defines a level of access bestowed (or withheld) by a [ACIv3PermissionBindRule].
*/
type ACIv3Permission struct {
	*aCIPermission
}

type aCIPermission struct {
	*bool
	*aCIRights
}

/*
Permission returns an instance of [ACIv3Permission] alongside an error following an attempt to marshal x.

If only a single value is provided, it is assumed to be the string representation of an [ACIv3Permission], e.g.:

	allow(read,search,compare)

If more than one values are provided, it is assumed the first argument is a disposition Boolean. A value of true
results in a granting [ACIv3Permission] ("allow"), while false results in a withholding [ACIv3Permission] ("deny").
All subsequent arguments are assumed to be individual [ACIv3Right] instances or their equivalent forms as integers
or strings.
*/
func (r NetscapeACIv3) Permission(x ...any) (ACIv3Permission, error) {
	return marshalACIv3Permission(x...)
}

func marshalACIv3Permission(x ...any) (ACIv3Permission, error) {
	var (
		p   *aCIPermission
		err error
	)

	switch len(x) {
	case 0:
		err = badACIv3PermErr
		return badACIv3Permission, err
	case 1:
		if raw, ok := x[0].(string); !ok || len(raw) == 0 {
			err = badACIv3PermErr
			return badACIv3Permission, err
		} else {
			p, err = parseACIv3Permission(raw)
		}
	default:
		if disp, ok := x[0].(bool); !ok {
			err = badACIv3PermErr
			return badACIv3Permission, err
		} else {
			p, err = newACIv3Permission(disp, x[1:]...)
		}
	}

	return ACIv3Permission{p}, err
}

/*
newACIv3Permission returns a newly initialized instance of *permission bearing the provided disposition and [ACIv3Right] instance(s).
*/
func newACIv3Permission(disp bool, x ...any) (p *aCIPermission, err error) {
	p = new(aCIPermission)
	p.bool = &disp
	p.aCIRights = newRights()
	p.shift(x...)
	return
}

func parseACIv3Permission(raw string) (p *aCIPermission, err error) {
	var offset int
	var disp bool

	if len(raw) < 9 {
		// shortest possible statement is 9 chars ("deny(all)"),
		// so bail out if we're smaller than that.
		err = badACIv3PermErr
		return
	} else if raw[len(raw)-1] != ')' {
		// must end in a closing paren
		err = badACIv3PermErr
		return
	}
	raw = removeWHSP(raw)

	if hasPfx(raw, "allow(") {
		offset = 6
		disp = true
	} else if hasPfx(raw, "deny(") {
		offset = 5
		disp = false
	} else {
		err = badACIv3PermErr
		return
	}

	raw = raw[offset:]     // chop disposition prefix
	raw = raw[:len(raw)-1] // chop closing paren

	// split the remaining text by comma delimiters.
	// shift the remainder, which should be one (1) or
	// more string-based "right" names (i.e.: "read").
	p, err = newACIv3Permission(disp, split(raw, ","))

	return
}

func (r *aCIPermission) shift(x ...any) {
	if !r.isZero() {
		// iterate through the sequence of "anys"
		// and assert to an ACIv3Right (or the abstraction
		// of an ACIv3Right).
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case int, ACIv3Right:
				r.aCIRights.cast().Shift(tv)
			case []int:
				for j := 0; j < len(tv); j++ {
					r.aCIRights.cast().Shift(tv[j])
				}
			case string:
				if priv, found := aCIRightsNames[lc(tv)]; found {
					r.aCIRights.cast().Shift(priv)
				}
			case []string:
				for j := 0; j < len(tv); j++ {
					if priv, found := aCIRightsNames[lc(tv[j])]; found {
						r.aCIRights.cast().Shift(priv)
					}
				}
			}
		}
	}
}

func (r *aCIPermission) unshift(x ...any) {
	if !r.isZero() {
		// iterate through the sequence of "anys"
		// and assert to an ACIv3Right (or the abstraction
		// of an ACIv3Right).
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case int, ACIv3Right:
				r.aCIRights.cast().Unshift(tv)
			case []int:
				for j := 0; j < len(tv); j++ {
					r.aCIRights.cast().Unshift(tv[j])
				}
			case string:
				if priv, found := aCIRightsNames[lc(tv)]; found {
					r.aCIRights.cast().Unshift(priv)
				}
			case []string:
				for j := 0; j < len(tv); j++ {
					if priv, found := aCIRightsNames[lc(tv[j])]; found {
						r.aCIRights.cast().Unshift(priv)
					}
				}
			}
		}
	}
}

func (r *aCIPermission) positive(x any) (posi bool) {
	if !r.isZero() {
		switch tv := x.(type) {
		case int:
			if posi = tv == 0 && r.aCIRights.cast().Int() == tv; posi {
				break
			}
			posi = r.aCIRights.cast().Positive(tv)

		case string:
			if priv, found := aCIRightsNames[lc(tv)]; found {
				posi = r.positive(priv)
			}

		case ACIv3Right:
			posi = r.positive(int(tv))
		}
	}
	return
}

/*
String returns a single string name value for receiver instance.
*/
func (r ACIv3Right) String() (p string) {
	switch r {
	case ACIv3NoAccess:
		return aCIRightsMap[0]
	case ACIv3AllAccess:
		return aCIRightsMap[895]
	}

	if kw, found := aCIRightsMap[r]; found {
		p = kw
	}
	return
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [ACIv3Right] instances currently being expressed. For example, if the receiver instance has its [ACIv3ReadAccess] and [ACIv3DeleteAccess] [ACIv3Right] bits enabled, this would represent an abstract length of two (2).
*/
func (r ACIv3Permission) Len() (l int) {
	if !r.IsZero() {
		l = r.aCIPermission.len()
	}
	return
}

func (r aCIPermission) len() int {
	var D int
	for i := 0; i < r.aCIRights.cast().Size(); i++ {
		if d := ACIv3Right(1 << i); r.aCIRights.cast().Positive(d) {
			D++
		}
	}

	return D
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3Permission) String() string {
	if r.IsZero() {
		return badACIv3PermStr
	}

	pint := r.aCIPermission.aCIRights.cast().Int()
	dispStr := func(rights []string) string {
		return r.Disposition() + `(` + join(rights, `,`) + `)`
	}

	var rights []string
	if ACIv3Right(pint) == ACIv3AllAccess {
		rights = append(rights, ACIv3AllAccess.String())
		return dispStr(rights)
	} else if pint == 1023 {
		rights = append(rights, ACIv3AllAccess.String())
		rights = append(rights, ACIv3ProxyAccess.String())
		return dispStr(rights)
	} else if ACIv3Right(pint) == ACIv3NoAccess {
		rights = append(rights, ACIv3NoAccess.String())
		return dispStr(rights)
	}

	size := r.aCIPermission.aCIRights.cast().Size()
	for i := 0; i < size; i++ {
		if right := ACIv3Right(1 << i); r.Positive(right) {
			rights = append(rights, right.String())
		}
	}

	return dispStr(rights)
}

/*
Disposition returns the string disposition `allow` or 'deny', depending on the state of the receiver.
*/
func (r ACIv3Permission) Disposition() string {
	if r.aCIPermission == nil {
		return `<unknown_disposition>`
	}
	return r.aCIPermission.disposition()
}

func (r aCIPermission) disposition() (disp string) {
	disp = `<unknown_disposition>`
	if *r.bool {
		disp = `allow`
	} else if !*r.bool {
		disp = `deny`
	}
	return
}

/*
Positive returns a Boolean value indicative of whether a particular bit is positive (is set). Negation implies negative, or unset.
*/
func (r ACIv3Permission) Positive(x any) (posi bool) {
	if err := r.Valid(); err == nil {
		posi = r.aCIPermission.positive(x)
	}
	return
}

/*
Shift left-shifts the receiver instance to include [ACIv3Right] x, if not already present.
*/
func (r ACIv3Permission) Shift(x ...any) ACIv3Permission {
	if err := r.Valid(); err == nil {
		for i := 0; i < len(x); i++ {
			r.aCIPermission.shift(x[i]) //rights.cast().Shift(x[i])
		}
	}
	return r
}

/*
Unshift right-shifts the receiver instance to remove [ACIv3Right] x, if present.
*/
func (r ACIv3Permission) Unshift(x ...any) ACIv3Permission {
	if err := r.Valid(); err == nil {
		for i := 0; i < len(x); i++ {
			r.aCIPermission.unshift(x[i]) //rights.cast().Unshift(x[i])
		}
	}
	return r
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3Permission) IsZero() bool {
	return r.aCIPermission.isZero()
}

func (r *aCIPermission) isZero() bool {
	if r == nil {
		return true
	}

	return r.bool == nil && r.aCIRights == nil
}

/*
Valid returns a non-error instance if the receiver fails to pass basic validity checks.
*/
func (r ACIv3Permission) Valid() (err error) {
	if !r.IsZero() {
		if r.aCIPermission.bool == nil {
			err = errorTxt("ACIv3Permission: missing disposition")
		}
	} else {
		err = nilInstanceErr
	}

	return
}

//// OID

/*
ACIv3ObjectIdentifier implements a storage type for slices of [NumericOID] instances.

Instances of this type are only used in [ACIv3TargetRuleItem] instances which bear either the
[ACIv3TargetCtrl] or [ACIv3TargetExtOp] keywords.
*/
type ACIv3ObjectIdentifier struct {
	ACIv3TargetKeyword
	*aCIObjectIdentifier
}

type aCIObjectIdentifier struct {
	slice []NumericOID // use string instead of proper DN type, as ACIv3 allows wildcard DNs
}

func (r aCIObjectIdentifier) string(mvq, pad bool) string {
	var s string
	if L := len(r.slice); L > 0 {
		var _s []string
		if mvq {
			for i := 0; i < L; i++ {
				_s = append(_s, `"`+r.slice[i].String()+`"`)
			}
		} else {
			for i := 0; i < L; i++ {
				_s = append(_s, r.slice[i].String())
			}
		}

		var delim string = `||`
		if pad {
			delim = ` || `
		}

		if s = join(_s, delim); !mvq {
			s = `"` + s + `"`
		}
	}

	return s
}

func (r aCIObjectIdentifier) contains(x any) bool {
	var contains bool
	var term string
	switch tv := x.(type) {
	case string:
		term = tv
	case NumericOID:
		term = tv.String()
	}

	for i := 0; i < len(r.slice) && !contains; i++ {
		contains = r.slice[i].String() == term
	}

	return contains
}

/*
TRM returns an instance of [ACIv3TargetRuleMethods].

Each of the return instance's key values represent a single [ACIv3Operator] that is allowed for use in the creation of [ACIv3TargetRuleItem] instances which bear the receiver instance as an expression value. The value for each key is the actual instance method to -- optionally -- use for the creation of the [ACIv3TargetRuleItem].

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3TargetRuleItem] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3ObjectIdentifier) TRM() ACIv3TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
LDAPControlOIDs initializes a new instance of [ACIv3ObjectIdentifier].

Instances of this design are used in the creation of [ACIv3TargetRuleItem] instances that bear the [ACIv3TargetCtrl] [ACIv3TargetKeyword] context.

OIDs produced as a result of this function are expected to be LDAP Control Object Identifiers. Input instances must be string or [NumericOID].
*/
func (r NetscapeACIv3) LDAPControlOIDs(x ...any) (ACIv3ObjectIdentifier, error) {
	return marshalACIv3ObjectIdentifier(ACIv3TargetCtrl, x...)
}

/*
LDAPExtendedOperationOIDs initializes a new instance of [ACIv3ObjectIdentifier].

Instances of this design are used in the creation of [ACIv3TargetRuleItem] instances that bear the [ACIv3TargetExtOp] [ACIv3TargetKeyword] context.

OIDs produced as a result of this function are expected to be LDAP Extended Operation Object Identifiers. Input instances must be string or [NumericOID].
*/
func (r NetscapeACIv3) LDAPExtendedOperationOIDs(x ...any) (ACIv3ObjectIdentifier, error) {
	return marshalACIv3ObjectIdentifier(ACIv3TargetExtOp, x...)
}

func marshalACIv3ObjectIdentifier(kw ACIv3TargetKeyword, x ...any) (r ACIv3ObjectIdentifier, err error) {
	r = ACIv3ObjectIdentifier{
		kw, // constrained by caller
		&aCIObjectIdentifier{},
	}

	for i := 0; i < len(x) && err == nil; i++ {
		_, err = r.push(x[i])
	}

	return
}

/*
IsZero wraps the [stackage.Stack.IsZero] method.
*/
func (r ACIv3ObjectIdentifier) IsZero() bool {
	return r.aCIObjectIdentifier == nil
}

/*
Push appends one (1) or more unique numeric OID values -- as string or [NumericOID] instances -- to
the receiver instance.
*/
func (r ACIv3ObjectIdentifier) Push(x ...any) ACIv3ObjectIdentifier {
	oid, _ := r.push(x...)
	return oid
}

func (r ACIv3ObjectIdentifier) push(x ...any) (ACIv3ObjectIdentifier, error) {
	var err error
	if !r.IsZero() {
		for i := 0; i < len(x) && err == nil; i++ {
			var oid NumericOID

			switch tv := x[i].(type) {
			case string:
				if oid, err = marshalNumericOID(tv); err == nil &&
					!r.aCIObjectIdentifier.contains(tv) {
					r.aCIObjectIdentifier.slice = append(r.aCIObjectIdentifier.slice, oid)
				}
			case NumericOID:
				if oid, err = marshalNumericOID(tv.String()); err == nil &&
					!r.aCIObjectIdentifier.contains(tv) {
					r.aCIObjectIdentifier.slice = append(r.aCIObjectIdentifier.slice, oid)
				}
			case ACIv3ObjectIdentifier:
				// In case the user wishes to "merge" multiple instances
				// of ACIv3ObjectIdentifier into one ...
				if err = tv.Valid(); err == nil {
					for i := 0; i < tv.Len() && err == nil; i++ {
						_, err = r.push(tv.Index(i))
					}
				}
			}
		}
	}

	return r, err
}

/*
Len wraps the [stackage.Stack.Len] method.
*/
func (r ACIv3ObjectIdentifier) Len() int {
	var i int
	if !r.IsZero() {
		i = len(r.aCIObjectIdentifier.slice)
	}

	return i
}

/*
Valid returns a Boolean value indicative of a valid receiver instance.
*/
func (r ACIv3ObjectIdentifier) Valid() error {
	var err error
	if r.ACIv3TargetKeyword == 0x0 || r.Len() == 0 {
		err = badACIv3OIDErr
	}

	return err
}

/*
Index returns the Nth instance of [NumericOID] present within the receiver instance.
*/
func (r ACIv3ObjectIdentifier) Index(idx int) NumericOID {
	var oid NumericOID
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			oid = r.aCIObjectIdentifier.slice[idx]
		}
	}

	return oid
}

/*
Eq returns an instance of [ACIv3TargetRuleItem] which represents a keyword-based equality
rule containing one (1) or more [NumericOID] instances.
*/
func (r ACIv3ObjectIdentifier) Eq() ACIv3TargetRuleItem {
	return r.newTR(ACIv3Eq)
}

/*
Ne returns an instance of [ACIv3TargetRuleItem] which represents a keyword-based negated
equality rule containing one (1) or more [NumericOID] instances.

Negated equality [ACIv3TargetRuleItem] instances should be used with caution.
*/
func (r ACIv3ObjectIdentifier) Ne() ACIv3TargetRuleItem {
	return r.newTR(ACIv3Ne)
}

func (r ACIv3ObjectIdentifier) newTR(op ACIv3Operator) ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(r.ACIv3TargetKeyword, op, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Keyword returns the [ACIv3TargetKeyword] associated with the receiver instance enveloped as a [ACIv3TargetKeyword]. In the context of this type instance, the [ACIv3TargetKeyword] returned is always [ACIv3TargetExtOp] or [ACIv3TargetCtrl].
*/
func (r ACIv3ObjectIdentifier) Keyword() ACIv3TargetKeyword {
	var kw ACIv3TargetKeyword
	if !r.IsZero() {
		kw = r.ACIv3TargetKeyword
	}

	return kw
}

/*
Contains returns a Boolean value indicative of whether value x, if a string or [NumericOID] instance, already resides within the receiver instance.

Case is not significant in the matching process.
*/
func (r ACIv3ObjectIdentifier) Contains(x any) bool {
	var contains bool
	if !r.IsZero() {
		contains = r.aCIObjectIdentifier.contains(x)
	}

	return contains
}

/*
SetQuotationStyle performs the iterative equivalent to the [ACIv3TargetRuleItem.SetQuotationStyle] method, activating
the specified quotation style upon all such instances present within the receiver instance.
*/
func (r ACIv3TargetRule) SetQuotationStyle(style int) ACIv3TargetRule {
	if !r.IsZero() {
		for i := 0; i < r.Len(); i++ {
			r.Index(i).SetQuotationStyle(style)
		}
	}

	return r
}

/*
SetQuotationStyle allows the election of a particular multivalued quotation style offered by the various adopters of the ACIv3 syntax. In the context of a [ACIv3TargetRuleItem], this will only have a meaningful impact if the keyword for the receiver is one (1) of the following:

  - [ACIv3TargetCtrl]  (targetcontrol)
  - [ACIv3TargetExtOp] (extop)
  - [ACIv3Target]      (target)
  - [ACIv3TargetTo]    (target_to)
  - [ACIv3TargetFrom]  (target_from)
  - [ACIv3TargetAttr]  (targetattr)

Additionally, the underlying type set as the expression value within the receiver MUST be a [ACIv3TargetDistinguishedName], [ACIv3Attribute] or [ACIv3ObjectIdentifier] instance with two (2) or more values present.
*/
func (r ACIv3TargetRuleItem) SetQuotationStyle(style int) ACIv3TargetRuleItem {
	if !r.IsZero() {
		switch r.Expression().(type) {
		case ACIv3TargetDistinguishedName, ACIv3Attribute, ACIv3ObjectIdentifier:
			switch r.Keyword() {
			case ACIv3Target, ACIv3TargetTo, ACIv3TargetFrom, ACIv3TargetAttr,
				ACIv3TargetCtrl, ACIv3TargetExtOp:
				r.aCITargetRuleItem.mvq = style == 0
			}
		}
	}

	return r
}

//// PERMISSION/BIND

/*
ACIv3PermissionBindRule contains one (1) or more [ACIv3PermissionBindRuleItem] instances.
*/
type ACIv3PermissionBindRule struct {
	*aCIPermissionBindRule
}

type aCIPermissionBindRule struct {
	slice []ACIv3PermissionBindRuleItem
}

func (r ACIv3PermissionBindRule) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIPermissionBindRule.slice)
	}

	return l
}

/*
Index returns the Nth [ACIv3PermissionBindRuleItem] slice within the receiver instance.
*/
func (r ACIv3PermissionBindRule) Index(idx int) ACIv3PermissionBindRuleItem {
	var p ACIv3PermissionBindRuleItem = badACIv3PBRItem
	if 0 <= idx && idx < r.Len() {
		p = r.aCIPermissionBindRule.slice[idx]
	}

	return p
}

/*
ACIv3PermissionBindRuleItem contains one (1) [ACIv3Permission] instance and one (1) [ACIv3BindRule]
instance. Instances of this type are used within an [ACIv3PermissionBindRule] instance.
*/
type ACIv3PermissionBindRuleItem struct {
	*aCIPermissionBindRuleItem
}

type aCIPermissionBindRuleItem struct {
	ACIv3Permission
	ACIv3BindRule
}

/*
PermissionBindRule returns an instance of [ACIv3PermissionBindRule] alongside an error following
an attempt to marshal x, which must be zero (0) or more instances of [ACIv3PermissionBindRuleItem]
or equivalent string values.
*/
func (r NetscapeACIv3) PermissionBindRule(x ...any) (ACIv3PermissionBindRule, error) {
	var (
		pbr ACIv3PermissionBindRule = ACIv3PermissionBindRule{&aCIPermissionBindRule{}}
		err error
	)

	if len(x) > 0 {
		pbr.Push(x...)
	}

	return pbr, err
}

/*
Push appends zero (0) or more valid instances of [ACIv3PermissionBindRuleItem], or
the string equivalents.
*/
func (r ACIv3PermissionBindRule) Push(x ...any) ACIv3PermissionBindRule {
	if !r.IsZero() {
		for i := 0; i < len(x); i++ {
			switch tv := x[i].(type) {
			case string:
				r.parse(tv)
			case ACIv3PermissionBindRuleItem:
				if err := tv.Valid(); err == nil {
					r.aCIPermissionBindRule.slice = append(r.aCIPermissionBindRule.slice, tv)
				}
			}

		}
	}

	return r
}

/*
PermissionBindRuleItem returns an instance of [ACIv3PermissionBindRuleItem], bearing the [ACIv3Permission] P and the [ACIv3BindRule]
B. The values P and B shall undergo validity checks per the conditions of the [ACIv3PermissionBindRuleItem] Valid method
automatically. A bogus [ACIv3PermissionBindRuleItem] is returned if such checks fail.

Instances of this kind are intended for append via the [ACIv3PermissionBindRule.Push] method
*/
func (r NetscapeACIv3) PermissionBindRuleItem(x ...any) (ACIv3PermissionBindRuleItem, error) {
	var (
		pbr ACIv3PermissionBindRuleItem = ACIv3PermissionBindRuleItem{&aCIPermissionBindRuleItem{}}
		err error
	)

	if len(x) == 0 {
		return pbr, err
	}

	switch tv := x[0].(type) {
	case string:
		err = pbr.parse(tv)
	case ACIv3Permission:
		if err = tv.Valid(); err == nil {
			if len(x) == 2 {
				b, ok := x[1].(ACIv3BindRule)
				if !ok {
					err = badACIv3PBRErr
				} else if err = b.Valid(); err == nil {
					pbr.aCIPermissionBindRuleItem.ACIv3Permission = tv
					pbr.aCIPermissionBindRuleItem.ACIv3BindRule = b
				}
			}
		}
	default:
		err = badACIv3PBRErr
	}

	return pbr, err
}

func (r *ACIv3PermissionBindRule) parse(x string) (err error) {
	if r.IsZero() {
		r.aCIPermissionBindRule = &aCIPermissionBindRule{}
	}

	if idx := lstridx(x, ";"); idx == -1 {
		err = badACIv3PBRErr
	} else {
		sp := split(x[:idx], ";")
		for i := 0; i < len(sp) && err == nil; i++ {
			var pb ACIv3PermissionBindRuleItem = ACIv3PermissionBindRuleItem{
				&aCIPermissionBindRuleItem{},
			}
			if len(sp[i]) > 0 {
				if err = pb.parse(trimS(sp[i]) + ";"); err == nil {
					r.Push(pb)
				}
			}
		}
	}

	return err
}

func (r *ACIv3PermissionBindRuleItem) parse(x string) (err error) {
	idx := idxr(x, ')')
	if idx == -1 {
		err = badACIv3PBRErr
		return
	}

	p, err := marshalACIv3Permission(x[:idx+1])
	if err == nil {
		idx2 := idxr(x, ';')
		if idx2 == -1 {
			err = badACIv3PBRErr
			return
		}

		var b ACIv3BindRule
		var tkz []aCIBindRuleToken
		if tkz, err = tokenizeACIv3BindRule(x[idx+2 : idx2]); err == nil {
			if b, err = parseACIv3BindRuleTokens(tkz); err == nil {
				r.aCIPermissionBindRuleItem = &aCIPermissionBindRuleItem{
					ACIv3Permission: p,
					ACIv3BindRule:   b,
				}
				err = r.Valid()
			}
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r ACIv3PermissionBindRule) IsZero() bool {
	return r.aCIPermissionBindRule == nil
}

/*
IsZero returns a Boolean value indicative of whether the receiver instance is nil, or unset.
*/
func (r ACIv3PermissionBindRuleItem) IsZero() bool {
	return r.aCIPermissionBindRuleItem == nil
}

/*
Permission returns the underlying [ACIv3Permission] instance present within the receiver instance.
*/
func (r ACIv3PermissionBindRuleItem) Permission() ACIv3Permission {
	var p ACIv3Permission = badACIv3Permission
	if !r.IsZero() {
		p = r.aCIPermissionBindRuleItem.ACIv3Permission
	}

	return p
}

/*
BindRule returns the underlying [ACIv3BindRule] instance present within the receiver instance.
*/
func (r ACIv3PermissionBindRuleItem) BindRule() ACIv3BindRule {
	var p ACIv3BindRule = badACIv3BindRule
	if !r.IsZero() {
		p = r.aCIPermissionBindRuleItem.ACIv3BindRule
	}

	return p
}

/*
Kind returns the string literal `permissionBindRule`.
*/
func (r ACIv3PermissionBindRule) Kind() string {
	return pbrRuleIDStr
}

/*
Kind returns the string literal `permissionBindRuleItem`.
*/
func (r ACIv3PermissionBindRuleItem) Kind() string {
	return pbrRuleItemIDStr
}

/*
Valid returns an error instance should any of the following conditions evaluate as true:

  - Valid returns an error for P
  - Valid returns an error for B
  - Len returns zero (0) for B
*/
func (r ACIv3PermissionBindRule) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	}

	return
}

/*
Valid returns an error following a validity scan of the receiver instance.
*/
func (r ACIv3PermissionBindRuleItem) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else {
		if err = r.aCIPermissionBindRuleItem.ACIv3Permission.Valid(); err == nil {
			err = r.aCIPermissionBindRuleItem.ACIv3BindRule.Valid()
		}
	}

	return
}

/*
String returns the string representation of the receiver.
*/
func (r ACIv3PermissionBindRule) String() string {
	var s []string
	if !r.IsZero() {
		for i := 0; i < r.Len(); i++ {
			pbr := r.aCIPermissionBindRule.slice[i]
			s = append(s, pbr.String())
		}
	}

	return join(s, " ")
}

/*
String returns the string representation of the receiver.
*/
func (r ACIv3PermissionBindRuleItem) String() string {
	var s string
	if !r.IsZero() {
		p := r.aCIPermissionBindRuleItem.ACIv3Permission
		b := r.aCIPermissionBindRuleItem.ACIv3BindRule
		if !p.IsZero() && !b.IsZero() {
			s += p.String() + " " + b.String() + ";"
		}
	}

	return s
}

//// TIME / DAY

/*
ACIv3Day represents the numerical abstraction of a single day of the week, such as Sunday (1).
*/
type ACIv3Day uint8

func marshalACIv3DayOfWeek(x ...any) (r ACIv3DayOfWeek, err error) {
	r = newDoW()

	switch len(x) {
	case 0:
		return
	case 1:
		switch tv := x[0].(type) {
		case string:
			r.Shift(tv)
		case ACIv3Day:
			r.Shift(tv)
		case ACIv3DayOfWeek:
			r = tv
		}
	default:
		r.Shift(x...)
	}

	err = r.Valid()

	return
}

/*
parse will iterate a comma-delimited list and verify each slice as a day of the week and return a [ACIv3DayOfWeek] instance alongside a Boolean value indicative of success.
*/
func (r ACIv3DayOfWeek) parse(dow string) (err error) {
	r = newDoW()
	X := split(repAll(dow, ` `, ``), `,`)
	for i := 0; i < len(X); i++ {
		dw := matchStrDoW(X[i])
		if dw == noDay {
			err = badACIv3DoWErr
			return
		}
		r.Shift(dw)
	}

	err = r.Valid()
	return
}

func matchDoW(d any) (D ACIv3Day) {
	D = noDay
	switch tv := d.(type) {
	case int:
		D = matchIntDoW(tv)
	case string:
		D = matchStrDoW(tv)
	case ACIv3Day:
		D = tv
	}

	return
}

func matchStrDoW(d string) (D ACIv3Day) {
	D = noDay
	switch lc(d) {
	case `sun`, `sunday`, `1`:
		D = Sun
	case `mon`, `monday`, `2`:
		D = Mon
	case `tues`, `tuesday`, `3`:
		D = Tues
	case `wed`, `wednesday`, `4`:
		D = Wed
	case `thur`, `thurs`, `thursday`, `5`:
		D = Thur
	case `fri`, `friday`, `6`:
		D = Fri
	case `sat`, `saturday`, `7`:
		D = Sat
	}

	return
}

func matchIntDoW(d int) (D ACIv3Day) {
	D = noDay
	switch d {
	case 1:
		D = Sun
	case 2:
		D = Mon
	case 3:
		D = Tues
	case 4:
		D = Wed
	case 5:
		D = Thur
	case 6:
		D = Fri
	case 7:
		D = Sat
	}

	return
}

/*
DoW initializes, shifts and returns a new instance of [ACIv3DayOfWeek] in one shot.
*/
func (r NetscapeACIv3) DayOfWeek(x ...any) (ACIv3DayOfWeek, error) {
	return newDoW().Shift(x...), nil
}

/*
Keyword returns the [ACIv3BindToD] [BindKeyword].
*/
func (r ACIv3DayOfWeek) Keyword() ACIv3Keyword {
	return ACIv3BindDoW
}

/*
Len returns the abstract integer length of the receiver, quantifying the number of [ACIv3Day] instances currently being expressed.

For example, if the receiver instance has its [Mon] and [Fri] [ACIv3Day] bits enabled, this would represent an abstract length of two (2).
*/
func (r ACIv3DayOfWeek) Len() int {
	var D int
	for i := 0; i < r.cast().Size(); i++ {
		if d := ACIv3Day(1 << i); r.cast().Positive(d) {
			D++
		}
	}

	return D
}

/*
Weekdays is a convenient prefabricator function that returns an instance of [ACIv3BindRule] automatically assembled to express a sequence of weekdays. The sequence "[Mon] through [Fri]" can also be expressed via the bit-shifted value of sixty-two (62). See the [ACIv3Day] constants for the specific numerals used for summation in this manner.

Supplying an invalid or nonapplicable [ACIv3Operator] to this method shall return a bogus [ACIv3BindRule] instance.
*/
func (r NetscapeACIv3) WeekdaysBindRule(cop any) (b ACIv3BindRule) {
	if c, meth := newDoW().Shift(Mon, Tues, Wed, Thur, Fri).BRM().index(cop); c.Valid() == nil {
		b = meth()
	}
	return
}

/*
Weekend is a convenient prefabricator function that returns an instance of [ACIv3BindRule] automatically assembled to express a sequence of [Sun] and [Sat] [ACIv3Day] instances. This sequence can also be expressed via the bit-shifted value of sixty-five (65). See the [ACIv3Day] constants for the specific numerals used for summation in this manner.

Supplying an invalid or nonapplicable [ACIv3Operator] to this method shall return a bogus [ACIv3BindRule] instance.
*/
func (r NetscapeACIv3) WeekendBindRule(cop any) (b ACIv3BindRule) {
	if c, meth := newDoW().Shift(Sun, Sat).BRM().index(cop); c.Valid() == nil {
		b = meth()
	}
	return
}

/*
Shift wraps [shifty.BitValue.Shift] method to allow for bit-shifting of the receiver (r) instance using various representations of any number of days (string, int or [ACIv3Day]).
*/
func (r ACIv3DayOfWeek) Shift(x ...any) ACIv3DayOfWeek {
	// initialize receiver r if zero.
	if r.IsZero() {
		r = newDoW()
	}

	// assert each dow's type and analyze.
	// If deemed a valid dow, left-shift
	// into d.
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case int, string:
			if dw := matchDoW(tv); dw != noDay {
				r.cast().Shift(dw)
			}
		case ACIv3Day:
			r.cast().Shift(tv)
		}
	}

	return r
}

/*
Positive wraps the [shifty.BitValue.Positive] method.
*/
func (r ACIv3DayOfWeek) Positive(x ACIv3Day) (posi bool) {
	if !r.IsZero() {
		posi = r.cast().Positive(x)
	}
	return
}

/*
Unshift wraps [shifty.BitValue.Unshift] method to allow for bit-unshifting of the receiver (r) instance using various representations of any number of days (string, int or [ACIv3Day]).
*/
func (r ACIv3DayOfWeek) Unshift(x ...any) ACIv3DayOfWeek {
	// can't unshift from nothing
	if r.IsZero() {
		return r
	}

	// assert each dow's type and analyze.
	// If deemed a valid dow, right-shift
	// out of d.
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case int, string:
			if dw := matchDoW(tv); dw != noDay {
				r.cast().Unshift(dw)
			}
		case ACIv3Day:
			r.cast().Unshift(tv)
		}
	}

	return r
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3DayOfWeek) IsZero() bool {
	return r.cast().Kind() == 0x0
}

/*
String returns the string representation of the receiver instance. At least one [ACIv3Day] should register as positive in order for a valid string return to ensue.
*/
func (r ACIv3DayOfWeek) String() (s string) {
	s = badDoWStr

	var dows []string
	for i := 0; i < r.cast().Size(); i++ {
		if day := ACIv3Day(1 << i); r.Positive(day) {
			dows = append(dows, day.String())
		}
	}

	if len(dows) > 0 {
		s = join(dows, `,`)
	}

	return
}

/*
Valid returns a Boolean value indicative of whether the receiver contains one or more valid bits representing known [ACIv3Day] values.

At least one [ACIv3Day] must be positive within the receiver.
*/
func (r ACIv3DayOfWeek) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.String() == badDoWStr {
		err = badACIv3DoWErr
	}

	return
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindDoW] [ACIv3BindKeyword] context.
*/
func (r ACIv3DayOfWeek) Eq() (b ACIv3BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(ACIv3BindDoW, ACIv3Eq, r)
	}
	return
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindDoW] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3DayOfWeek) Ne() (b ACIv3BindRule) {
	if err := r.Valid(); err == nil {
		b = newACIv3BindRuleItem(ACIv3BindDoW, ACIv3Ne, r)
	}
	return
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator]
type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the
receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod]
instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances
apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the
execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances.
While this is useful in unit testing, the end user must only execute this method IF and WHEN the
receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3DayOfWeek) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
String returns a single string name value for receiver instance of [ACIv3Day].
*/
func (r ACIv3Day) String() (day string) {
	day = badDoWStr
	switch r {
	case Sun:
		day = `Sun`
	case Mon:
		day = `Mon`
	case Tues:
		day = `Tues`
	case Wed:
		day = `Wed`
	case Thur:
		day = `Thur`
	case Fri:
		day = `Fri`
	case Sat:
		day = `Sat`
	}

	return
}

/*
ACIv3TimeOfDay is a [2]byte type used to represent a specific point in 24-hour time
using hours and minutes (such as 1215 for 12:15 PM, or 1945 for 7:45 PM). Instances
of this type contain a big endian unsigned 16-bit integer value, one that utilizes
the first and second slices. The value is used within [ACIv3BindToD]-based [ACIv3BindRule]
statements.
*/
type ACIv3TimeOfDay struct {
	*aCITimeOfDay
}

/*
ToD initializes, sets and returns a new instance of [TimeOfDay] in one shot.
*/
func (r NetscapeACIv3) TimeOfDay(x ...any) (ACIv3TimeOfDay, error) {
	return marshalACIv3TimeOfDay(x...)
}

func marshalACIv3TimeOfDay(x ...any) (r ACIv3TimeOfDay, err error) {
	r.aCITimeOfDay = new(aCITimeOfDay)
	switch len(x) {
	case 0:
	default:
		switch tv := x[0].(type) {
		case string:
			r.Set(x[0])
		case ACIv3TimeOfDay:
			r.Set(tv.String())
		}
	}

	err = r.Valid()

	return
}

type aCITimeOfDay [2]byte

/*
TimeframeBindRule is a convenience function that returns a [ACIv3BindRule] instance for the purpose of expressing a timeframe during which access may (or may not) be granted. This is achieved by combining the two (2) [ACIv3TimeOfDay] input values in a Boolean "AND stack".

The notBefore input value defines the so-called "start" of the timeframe. It should be chronologically earlier than notAfter. This value will be used to craft a Greater-Than-Or-Equal (Ge) [ACIv3BindRule] expressive statement.

The notAfter input value defines the so-called "end" of the timeframe. It should be chronologically later than notBefore. This value will be used to craft a Less-Than (Lt) [ACIv3BindRule] expressive statement.
*/
func (r NetscapeACIv3) TimeframeBindRule(notBefore, notAfter ACIv3TimeOfDay) ACIv3BindRule {
	return ACIv3BindRuleAnd{&aCIBindRuleSlice{
		slice: []ACIv3BindRule{notBefore.Ge(), notAfter.Lt()},
	}}
}

/*
Keyword wraps the [stackage.Condition.Keyword] method and resolves the raw value into a [BindKeyword]. Failure to do so will return a bogus [Keyword].
*/
func (r ACIv3TimeOfDay) Keyword() ACIv3Keyword {
	return ACIv3BindToD
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindToD] [BindKeyword] context.
*/
func (r ACIv3TimeOfDay) Eq() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Eq, r)
	}
	return br
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindToD] [BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3TimeOfDay) Ne() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Ne, r)
	}
	return br
}

/*
Lt initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Less-Than the [ACIv3BindToD] [BindKeyword] context.
*/
func (r ACIv3TimeOfDay) Lt() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Lt, r)
	}
	return br
}

/*
Le initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Less-Than-Or-Equal to the [ACIv3BindToD] [BindKeyword] context.
*/
func (r ACIv3TimeOfDay) Le() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Le, r)
	}
	return br
}

/*
Gt initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Greater-Than the [ACIv3BindToD] [BindKeyword] context.
*/
func (r ACIv3TimeOfDay) Gt() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Gt, r)
	}
	return br
}

/*
Ge initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Greater-Than-Or-Equal to the [ACIv3BindToD] [BindKeyword] context.
*/
func (r ACIv3TimeOfDay) Ge() ACIv3BindRule {
	br := badACIv3BindRule
	if err := r.Valid(); err == nil {
		br = newACIv3BindRuleItem(ACIv3BindToD, ACIv3Ge, r)
	}

	return br
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3TimeOfDay) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
		ACIv3Lt: r.Lt,
		ACIv3Le: r.Le,
		ACIv3Gt: r.Gt,
		ACIv3Ge: r.Ge,
	})
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3TimeOfDay) String() string {
	s := badToDStr
	if !r.IsZero() {
		s = itoa(int(uint16g([]byte{r.aCITimeOfDay[0], r.aCITimeOfDay[1]})))
		for len(s) < 4 {
			s = "0" + s
		}
	}

	return s
}

/*
Valid returns a Boolean value indicative of whether the receiver is believed to be in a valid state.
*/
func (r ACIv3TimeOfDay) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	}
	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3TimeOfDay) IsZero() bool {
	return r.aCITimeOfDay == nil
}

/*
Set encodes the specified 24-hour (a.k.a.: military) time value into the receiver instance.

Valid input types are string and [time.Time]. The effective hour and minute values, when combined, should ALWAYS fall within the valid clock range of 0000 up to and including 2400.  Bogus values within said range, such as 0477, will return an error.
*/
func (r ACIv3TimeOfDay) Set(t any) ACIv3TimeOfDay {
	r.aCITimeOfDay.set(t)
	return r
}

func (r *aCITimeOfDay) set(t any) {
	assertToD(r, t)
}

/*
assertToD is called by timeOfDay.set for the purpose of handling a potential clock time value for use in a [ACIv3BindRule] statement.
*/
func assertToD(r *aCITimeOfDay, t any) {
	if r == nil {
		r = new(aCITimeOfDay)
	}
	switch tv := t.(type) {
	case time.Time:
		// time.Time input results in a recursive
		// run of this method.
		if !tv.IsZero() {
			h := itoa(tv.Hour())
			m := itoa(tv.Minute())
			if len(h) > 1 {
				h = "0" + h
			}
			if len(m) > 1 {
				m = "0" + m
			}
			r.set(h + m)
		}
	case string:
		// Handle discrepancy between ACIv3 time, which ends
		// at 2400, and Golang Time, which ends at 2359.
		var offset int
		if tv == `2400` {
			tv = `2359` // so time.Parse doesn't flip
			offset = 41 // so we can use it as intended per ACIv3 time syntax.
		}

		if _, err := time.Parse(`1504`, tv); err == nil {
			if n, err := atoi(tv); err == nil {
				x := make([]byte, 2)
				uint16p(x, uint16(n+offset))
				for i := 0; i < 2; i++ {
					(*r)[i] = x[i]
				}
			}
		}
	}
}

//// SCOPE

/*
ACIv3Scope extends the standard RFC4511 [SearchScope] type to accommodate an additional
scope, "subordinate", for use in ACIv3-specific [URL]s, as well as for [ACIv3TargetRuleItem]
composition where the [ACIv3TargetScope] keyword is in use.
*/
type ACIv3Scope SearchScope

/*
Scope initializes, sets and returns an instance of [ACIv3Scope] in one shot. Valid
input types are as follows:

  - Standard scope names as string values (e.g.: `base`, `onelevel`, `subtree` and `subordinate`)
  - Integer representations of scopes (see the predefined [ACIv3Scope] constants for details)

This function may only be needed in certain situations where a scope needs to be
parsed from values with different representations. Usually the predefined [ACIv3Scope]
constants are sufficient.
*/
func (r NetscapeACIv3) SearchScope(x ...any) (s ACIv3Scope, err error) {
	return marshalACIv3SearchScope(x...)
}

func marshalACIv3SearchScope(x ...any) (s ACIv3Scope, err error) {
	s = badACIv3Scope
	if len(x) > 0 {
		switch tv := x[0].(type) {
		case string:
			s = aCIStrToScope(tv)
		case int:
			s = aCIIntToScope(tv)
		default:
			err = badACIv3ScopeErr
		}
	} else {
		err = badACIv3ScopeErr
	}

	return
}

/*
Eq initializes and returns a new [ACIv3TargetRuleItem] instance configured to express the
evaluation of the receiver value as Equal-To an [ACIv3TargetScope] [ACIv3TargetKeyword]
context.
*/
func (r ACIv3Scope) Eq() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem

	if r != badACIv3Scope {
		tr, _ = newACIv3TargetRuleItem(ACIv3TargetScope, ACIv3Eq, r)
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to
[ACIv3TargetRuleItem] instances that bear the [ACIv3TargetScope] [ACIv3TargetKeyword].

This method exists solely to satisfy Go's interface signature requirements.

This method SHALL NOT appear within instances of [ACIv3TargetRuleMethods] that
were crafted through execution of the [ACIv3Scope.TRM] method.
*/
func (r ACIv3Scope) Ne() ACIv3TargetRuleItem { return badACIv3TargetRuleItem }

/*
Keyword returns the [ACIv3Keyword] associated with the receiver instance enveloped
as a [ACIv3Keyword]. In the context of this type instance, the [ACIv3TargetKeyword]
returned is always [ACIv3TargetScope].
*/
func (r ACIv3Scope) Keyword() ACIv3Keyword {
	return ACIv3TargetScope
}

/*
TRM returns an instance of [ACIv3TargetRuleMethods].

Each of the return instance's key values represent a single [ACIv3Operator] that
is allowed for use in the creation of [ACIv3TargetRuleItem] instances which bear the
receiver instance as an expression value. The value for each key is the actual
instance method to -- optionally -- use for the creation of the [ACIv3TargetRuleItem].

This is merely a convenient alternative to maintaining knowledge of which
[ACIv3Operator] instances apply to which types. Instances of this type are also
used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet
been initialized, the execution of ANY of the return instance's value methods
will return bogus [ACIv3TargetRuleItem] instances. While this is useful in unit testing,
the end user must only execute this method IF and WHEN the receiver has been properly
populated and prepared for such activity.
*/
func (r ACIv3Scope) TRM() ACIv3TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{ACIv3Eq: r.Eq})
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3Scope) String() string {
	s := badSearchScope

	switch r {
	case ACIv3Scope(ScopeBaseObject):
		s = `base`
	case ACIv3Scope(ScopeSingleLevel):
		s = `onelevel`
	case ACIv3Scope(ScopeSubtree):
		s = `subtree`
	case ACIv3ScopeSubordinate:
		s = `subordinate` // seems to be an OUD thing.
	}

	return s
}

/*
strToScope returns an [ACIv3Scope] constant based on the string input. If a match does not occur, [ScopeBaseObject] (default)
is returned.
*/
func aCIStrToScope(x string) (s ACIv3Scope) {
	s = ACIv3Scope(ScopeBaseObject)
	switch lc(x) {
	case `one`, `onelevel`:
		s = ACIv3Scope(ScopeSingleLevel)
	case `sub`, `subtree`:
		s = ACIv3Scope(ScopeSubtree)
	case `children`, `subordinate`:
		s = ACIv3ScopeSubordinate
	}

	return
}

/*
intToScope returns an [ACIv3Scope] constant based on the integer input. If a match does not occur, [ScopeBaseObject] (default)
is returned.
*/
func aCIIntToScope(x int) (s ACIv3Scope) {
	s = ACIv3Scope(ScopeBaseObject) //default
	switch x {
	case 2:
		s = ACIv3Scope(ScopeSingleLevel)
	case 3:
		s = ACIv3Scope(ScopeSubtree)
	case 4:
		s = ACIv3ScopeSubordinate
	}

	return
}

//// ATTRIBUTE+FILTER

/*
AttributeFilter is a struct type that embeds an [ACIv3Attribute] and filter-style [ACIv3TargetRule].
*/
type ACIv3AttributeFilter struct {
	*aCIAttributeFilter
}

/*
aCIAttributeFilter is the embedded type (as a pointer!) within instances of ACIv3AttributeFilter.
*/
type aCIAttributeFilter struct {
	ACIv3Attribute // single LDAP AttributeType
	Filter         // single LDAP Search Filter
}

type ACIv3AttributeFilterOperationItem struct {
	*aCIAttributeFilterOperationItem
}

type aCIAttributeFilterOperationItem struct {
	ACIv3AttributeOperation                        // add= or delete=
	slice                   []ACIv3AttributeFilter // 1* ACIv3AttributeFilter; "&&" delim
}

/*
ACIv3AttributeFilterOperation is the high-level composite type for use in creating [ACIv3TargetRule]
instances which bear the [ACIv3TargetAttrFilters] [ACIKeyword].

Instances of this type require one (1) [ACIv3AddOp]-based [ACIv3AttributeFilterOperationItem] instance
and/or one (1) [ACIv3DelOp]-based [ACIv3AttributeFilterOperationItem] instance.
*/
type ACIv3AttributeFilterOperation struct {
	*aCIAttributeFilterOperation
}

type aCIAttributeFilterOperation struct {
	add  ACIv3AttributeFilterOperationItem
	del  ACIv3AttributeFilterOperationItem
	semi bool // when true, override default comma (",") delimiter with semicolon (";")
}

/*
AttributeOperation defines either an Add Operation or a Delete Operation.

Constants of this type are used in [ACIv3AttributeFilterOperation] instances.
*/
type ACIv3AttributeOperation uint8

/*
AF initializes, optionally sets and returns a new instance of [ACIv3AttributeFilter], which is a critical component of the [ACIv3TargetAttrFilters] Target Rule.

Input values must be either a [Filter] or an [ACIv3Attribute].
*/
func (r NetscapeACIv3) AttributeFilter(x ...any) (ACIv3AttributeFilter, error) {
	var (
		af  ACIv3AttributeFilter
		err error
	)

	switch len(x) {
	case 0:
		return af, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = af.parse(tv)
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		af.aCIAttributeFilter = &aCIAttributeFilter{}
		switch tv := x[0].(type) {
		case string:
			if isAttribute(tv) {
				af.aCIAttributeFilter.ACIv3Attribute, err = marshalACIv3Attribute(tv)

				switch tv2 := x[1].(type) {
				case Filter:
					af.aCIAttributeFilter.Filter = tv2
				case string:
					af.aCIAttributeFilter.Filter, err = marshalFilter(tv2)
				default:
					err = badACIv3AFOpItemErr
				}
			}
		case ACIv3Attribute:
			if err = tv.Valid(); err == nil {
				af.aCIAttributeFilter.ACIv3Attribute = tv

				switch tv2 := x[1].(type) {
				case Filter:
					af.aCIAttributeFilter.Filter = tv2
				case string:
					af.aCIAttributeFilter.Filter, err = marshalFilter(tv2)
				default:
					err = badACIv3AFOpItemErr
				}
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = af.Valid()
	}

	return af, err

}

func (r NetscapeACIv3) AttributeFilterOperationItem(x ...any) (ACIv3AttributeFilterOperationItem, error) {
	return marshalACIv3AttributeFilterOperationItem(x...)
}

func marshalACIv3AttributeFilterOperationItem(x ...any) (ACIv3AttributeFilterOperationItem, error) {
	afoi := ACIv3AttributeFilterOperationItem{&aCIAttributeFilterOperationItem{}}
	var err error

	switch len(x) {
	case 0:
		return afoi, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			err = afoi.parse(tv)
		case ACIv3AttributeFilterOperationItem:
			err = tv.Valid()
			afoi = tv
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		switch tv := x[0].(type) {
		case ACIv3AttributeOperation:
			switch tv2 := x[1].(type) {
			case ACIv3AttributeFilter:
				afoi.aCIAttributeFilterOperationItem.ACIv3AttributeOperation = tv
				afoi.aCIAttributeFilterOperationItem.slice = []ACIv3AttributeFilter{tv2}
			default:
				err = badACIv3AFOpItemErr
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = afoi.Valid()
	}

	return afoi, err
}

func (r NetscapeACIv3) AttributeFilterOperation(x ...any) (ACIv3AttributeFilterOperation, error) {
	return marshalACIv3AttributeFilterOperation(x...)
}

func marshalACIv3AttributeFilterOperation(x ...any) (ACIv3AttributeFilterOperation, error) {
	afo := ACIv3AttributeFilterOperation{&aCIAttributeFilterOperation{}}
	var err error

	switch len(x) {
	case 0:
		return afo, err
	case 1:
		switch tv := x[0].(type) {
		case string:
			var addPart, delPart string
			var semi bool
			addPart, delPart, semi, err = splitACIv3AttributeFilterOperation(tv)
			afo.aCIAttributeFilterOperation.semi = semi
			if addPart != "" {
				var add ACIv3AttributeFilterOperationItem
				add, err = marshalACIv3AttributeFilterOperationItem(addPart)
				afo.aCIAttributeFilterOperation.add = add
			}
			if delPart != "" {
				var del ACIv3AttributeFilterOperationItem
				del, err = marshalACIv3AttributeFilterOperationItem(delPart)
				afo.aCIAttributeFilterOperation.del = del
			}
		case ACIv3AttributeFilterOperation:
			afo = tv
			err = tv.Valid()
		default:
			err = badACIv3AFOpItemErr
		}
	case 2:
		switch x[0].(type) {
		case ACIv3AttributeOperation:
			switch tv2 := x[1].(type) {
			case ACIv3AttributeFilterOperationItem:
				if tv2.Operation() == ACIv3AddOp {
					afo.aCIAttributeFilterOperation.add = tv2
				} else if tv2.Operation() == ACIv3DelOp {
					afo.aCIAttributeFilterOperation.del = tv2
				}
			default:
				err = badACIv3AFOpItemErr
			}
		default:
			err = badACIv3AFOpItemErr
		}
	default:
		err = badACIv3AFOpItemErr
	}

	if err == nil {
		err = afo.Valid()
	}

	return afo, err
}

/*
Set assigns the provided address component to the receiver and returns the receiver instance in fluent-form.

Multiple values can be provided in variadic form, or piecemeal.
*/
func (r *ACIv3AttributeFilter) Set(x ...any) *ACIv3AttributeFilter {
	if r.IsZero() {
		r.aCIAttributeFilter = new(aCIAttributeFilter)
	}

	r.aCIAttributeFilter.set(x...)
	return r
}

/*
AttributeType returns the underlying instance of [ACIv3Attribute], or a bogus [ACIv3Attribute] if unset.
*/
func (r ACIv3AttributeFilter) Attribute() ACIv3Attribute {
	var a ACIv3Attribute = badACIv3Attribute
	if !r.IsZero() {
		a = r.aCIAttributeFilter.ACIv3Attribute
	}

	return a
}

/*
Filter returns the underlying instance of [Filter], or a bogus [Filter] if unset.
*/
func (r ACIv3AttributeFilter) Filter() Filter {
	var f Filter = invalidFilter{}
	if !r.IsZero() {
		f = r.aCIAttributeFilter.Filter
	}

	return f
}

/*
set is a private method called by AttributeFilter.Set.
*/
func (r *aCIAttributeFilter) set(x ...any) {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			if isAttribute(tv) {
				r.ACIv3Attribute, _ = marshalACIv3Attribute(tv)
			} else {
				r.Filter, _ = marshalFilter(tv)
			}
		case ACIv3Attribute:
			r.ACIv3Attribute = tv
		case Filter:
			r.Filter = tv
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AttributeFilter) String() string {
	var s string
	if err := r.Valid(); err == nil {
		s = r.aCIAttributeFilter.ACIv3Attribute.Index(0) + ":" + r.aCIAttributeFilter.Filter.String()
	}

	return s
}

/*
Keyword returns the [ACIv3TargetKeyword] associated with the receiver instance enveloped as a [ACIv3Keyword]. In the context of this type instance, the [ACIv3TargetKeyword] returned is always [ACIv3TargetFilter].
*/
func (r ACIv3AttributeFilter) Keyword() ACIv3Keyword {
	return ACIv3TargetAttrFilters
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r ACIv3AttributeFilter) Valid() (err error) {
	if r.IsZero() {
		err = nilInstanceErr
	} else if r.aCIAttributeFilter.Filter == nil {
		err = endOfFilterErr
	} else if r.aCIAttributeFilter.ACIv3Attribute.IsZero() {
		err = badACIv3AttributeErr
	}

	return
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3AttributeFilter) IsZero() bool {
	if r.aCIAttributeFilter == nil {
		return true
	}
	return r.aCIAttributeFilter.Filter == nil &&
		r.aCIAttributeFilter.ACIv3Attribute.IsZero()
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AttributeOperation) String() string {
	var o string = `add`
	if r == ACIv3DelOp {
		o = `delete`
	}

	return o
}

/*
Keyword returns the [ACIv3TargetKeyword] associated with the receiver instance. In the context of this type instance, the [ACIv3TargetKeyword] returned is always [ACIv3TargetAttrFilters].
*/
func (r ACIv3AttributeFilterOperation) Keyword() ACIv3Keyword {
	return ACIv3TargetAttrFilters
}

/*
SetDelimiter controls the delimitation scheme employed by the receiver. A value of one (1) overrides the default
comma (",") delimiter with a semicolon (";").
*/
func (r ACIv3AttributeFilterOperation) SetDelimiter(i ...int) ACIv3AttributeFilterOperation {
	if !r.IsZero() {
		if len(i) == 0 {
			r.aCIAttributeFilterOperation.semi = false
		} else {
			r.aCIAttributeFilterOperation.semi = i[0] == 1
		}
	}

	return r
}

/*
Len returns the integer length of the receiver instance. The maximum length for instances of this
kind is two (2).
*/
func (r ACIv3AttributeFilterOperation) Len() int {
	var l int
	if !r.IsZero() {
		if !r.aCIAttributeFilterOperation.add.IsZero() {
			l++
		}
		if !r.aCIAttributeFilterOperation.del.IsZero() {
			l++
		}
	}

	return l
}

/*
IsZero wraps the [stackage.Stack.IsZero] method.
*/
func (r ACIv3AttributeFilterOperation) IsZero() bool {
	var z bool = true
	if r.aCIAttributeFilterOperation != nil {
		z = r.aCIAttributeFilterOperation.add.IsZero() &&
			r.aCIAttributeFilterOperation.del.IsZero()
	}

	return z
}

/*
Valid wraps the [stackage.Stack.Valid] method.
*/
func (r ACIv3AttributeFilterOperation) Valid() error {
	var err error
	if r.IsZero() {
		err = nilInstanceErr
	}

	return err
}

/*
Kind returns the categorical label assigned to the receiver.
*/
func (r ACIv3AttributeFilterOperation) Kind() string {
	return ACIv3TargetAttrFilters.String()
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AttributeFilterOperation) String() string {
	var s string
	if !r.IsZero() {
		var sl []string
		if !r.aCIAttributeFilterOperation.add.IsZero() {
			sl = append(sl, r.aCIAttributeFilterOperation.add.String())
		}
		if !r.aCIAttributeFilterOperation.del.IsZero() {
			sl = append(sl, r.aCIAttributeFilterOperation.del.String())
		}

		var d string = ","
		if r.aCIAttributeFilterOperation.semi {
			d = ";"
		}
		s = join(sl, d)
	}

	return s
}

/*
Eq initializes and returns a new [ACIv3TargetRule] instance configured to express the evaluation of the receiver value as Equal-To a [ACIv3TargetAttrFilters] [ACIv3TargetKeyword] context.
*/
func (r ACIv3AttributeFilterOperation) Eq() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(ACIv3TargetAttrFilters, ACIv3Eq, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to [ACIv3TargetRule] instances that bear the [ACIv3TargetAttrFilters] [ACIv3TargetKeyword] context.

This method exists solely to convey this message and conform to Go's interface qualifying signature. When executed, this method will return a bogus [ACIv3TargetRule].

Negated equality [ACIv3TargetRule] instances should be used with caution.
*/
func (r ACIv3AttributeFilterOperation) Ne() ACIv3TargetRuleItem { return badACIv3TargetRuleItem }

/*
TRM returns an instance of [ACIv3TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3TargetRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3TargetRuleMethod] instance for  OPTIONAL use in the creation of a [ACIv3TargetRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type  are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3TargetRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3AttributeFilterOperation) TRM() ACIv3TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

func (r ACIv3AttributeFilterOperationItem) Push(x ...any) ACIv3AttributeFilterOperationItem {
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			_ = r.parse(tv)
		case ACIv3AttributeFilter:
			if tv.Valid() == nil {
				r.aCIAttributeFilterOperationItem.slice =
					append(r.aCIAttributeFilterOperationItem.slice, tv)
			}
		}
	}

	return r
}

/*
Keyword returns the [TargetKeyword] associated with the receiver instance enveloped as a [Keyword]. In the context of this type instance, the [TargetAttrFilters] [TargetKeyword] context is always returned.
*/
func (r ACIv3AttributeFilterOperationItem) Keyword() ACIv3Keyword {
	return ACIv3TargetAttrFilters
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3AttributeFilterOperationItem) Len() int {
	var l int
	if !r.IsZero() {
		l = len(r.aCIAttributeFilterOperationItem.slice)
	}

	return l
}

/*
Index returns the Nth instance of [ACIv3AttributeFilter] present within the receiver instance.
*/
func (r ACIv3AttributeFilterOperationItem) Index(idx int) ACIv3AttributeFilter {
	var af ACIv3AttributeFilter
	if !r.IsZero() {
		if 0 <= idx && idx < r.Len() {
			af = r.aCIAttributeFilterOperationItem.slice[idx]
		}
	}

	return af
}

/*
Contains returns a Boolean value indicative of whether the type and its value were located within the receiver.

Valid input types are [ACIv3AttributeFilter] or a valid string equivalent.

Case is significant in the matching process.
*/
func (r ACIv3AttributeFilterOperationItem) Contains(x any) bool {
	var found bool
	if r.Len() == 0 {
		return found
	}

	var candidate string

	switch tv := x.(type) {
	case string:
		candidate = tv
	case ACIv3AttributeFilter:
		candidate = tv.String()
	default:
		return found
	}

	for i := 0; i < r.Len() && !found; i++ {
		// case is significant here.
		found = r.Index(i).String() == candidate
	}

	return found
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ACIv3AttributeFilterOperationItem) IsZero() bool {
	return r.aCIAttributeFilterOperationItem == nil
}

/*
Valid returns an error following an analysis of the receiver instance.
*/
func (r ACIv3AttributeFilterOperationItem) Valid() error {
	var err error

	if !r.IsZero() {
		if r.aCIAttributeFilterOperationItem.ACIv3AttributeOperation == 0 ||
			len(r.aCIAttributeFilterOperationItem.slice) == 0 {
			err = badACIv3AFOpItemErr
		}
	}

	return err
}

/*
Kind returns the kind of receiver instance.
*/
func (r ACIv3AttributeFilterOperationItem) Kind() string {
	return ACIv3TargetAttrFilters.String()
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AttributeFilterOperationItem) String() string {
	var s string
	if !r.IsZero() {
		s = r.Operation().String() + `=`
		var f []string
		for i := 0; i < r.Len(); i++ {
			f = append(f, r.Index(i).String())
		}
		s += join(f, ` && `)
	}

	return s
}

/*
Eq initializes and returns a new [TargetRule] instance configured to express the evaluation of the receiver value as Equal-To a [TargetAttrFilters] [TargetKeyword] context.
*/
func (r ACIv3AttributeFilterOperationItem) Eq() ACIv3TargetRuleItem {
	var tr ACIv3TargetRuleItem = badACIv3TargetRuleItem
	t, err := newACIv3TargetRuleItem(ACIv3TargetAttrFilters, ACIv3Eq, r)
	if err == nil {
		tr = t
	}

	return tr
}

/*
Ne performs no useful task, as negated equality comparison does not apply to [ACIv3TargetRule] instances that bear the [ACIv3TargetAttrFilters] [ACIv3TargetKeyword] context.

This method exists solely to convey this message and conform to Go's interface qualifying signature. When executed, this method will return a bogus [ACIv3TargetRule].

Negated equality [ACIv3TargetRule] instances should be used with caution.
*/
func (r ACIv3AttributeFilterOperationItem) Ne() ACIv3TargetRuleItem { return badACIv3TargetRuleItem }

/*
TRM returns an instance of [ACIv3TargetRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3TargetRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3TargetRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3TargetRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3TargetRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3AttributeFilterOperationItem) TRM() ACIv3TargetRuleMethods {
	return newACIv3TargetRuleMethods(aCITargetRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Operation returns [ACIv3AddOp], [ACIv3DelOp] or an invalid operation if unspecified.
*/
func (r ACIv3AttributeFilterOperationItem) Operation() ACIv3AttributeOperation {
	var o ACIv3AttributeOperation
	if !r.IsZero() {
		o = r.aCIAttributeFilterOperationItem.ACIv3AttributeOperation
	}

	return o
}

// countACIv3AFOSubstr returns how many times substr occurs in s.
func countACIv3AFOSubstr(s, substr string) int {
	count := 0
	for {
		i := stridx(s, substr)
		if i == -1 {
			break
		}
		count++
		s = s[i+len(substr):]
	}
	return count
}

func splitACIv3AttributeFilterOperation(x string) (part1, part2 string, semi bool, err error) {
	// Trim the entire input first.
	s := trimS(x)

	// Find the delimiter (comma or semicolon) in the string.
	idx := idxany(s, ",;")
	if idx == -1 {
		// No delimiter; only one value.
		part1 = s
	} else {
		semi = rune(s[idx]) == ';'

		// Split the string into two parts. We use TrimSpace
		// to allow optional spaces after the delimiter.
		part1 = trimS(s[:idx])
		part2 = trimS(s[idx+1:])
		if len(part2) == 0 {
			err = errorTxt("empty second value after delimiter")
			return
		}
	}

	// Scan final result for conflicts
	err = checkACIv3AFOSubstr(part1, part2)
	return
}

func checkACIv3AFOSubstr(part1, part2 string) (err error) {
	// Each part must start with "add=" or "delete=".
	if !hasPfx(part1, "add=") && !hasPfx(part1, "delete=") {
		err = errorTxt("first part must start with 'add=' or 'delete='")
	} else if part2 != "" && !hasPfx(part2, "add=") && !hasPfx(part2, "delete=") {
		err = errorTxt("second part must start with 'add=' or 'delete='")
	} else if countACIv3AFOSubstr(part1, "add=") > 1 || countACIv3AFOSubstr(part1, "delete=") > 1 ||
		countACIv3AFOSubstr(part2, "add=") > 1 || countACIv3AFOSubstr(part2, "delete=") > 1 {
		err = errorTxt("prefix appears more than once in one of the parts")
	} else if part2 != "" {
		if (hasPfx(part1, "add=") && hasPfx(part2, "add=")) ||
			(hasPfx(part1, "delete=") && hasPfx(part2, "delete=")) {
			err = errorTxt("duplicate prefix in both parts")
		}
	}

	return
}

/*
parseACIv3AttributeFilterOperationItem parses the string input value (raw) and attempts to marshal its contents into an instance of AttributeFilterOperation (afo). An error is returned alongside afo upon completion of the attempt.
*/
func (r *ACIv3AttributeFilterOperationItem) parse(raw string) error {
	r.aCIAttributeFilterOperationItem = &aCIAttributeFilterOperationItem{}

	aop, val, err := parseACIv3AttrFilterOperPreamble(raw)
	if err == nil {
		r.aCIAttributeFilterOperationItem.ACIv3AttributeOperation = aop
		sp := split(val, `&&`)
		for i := 0; i < len(sp); i++ {
			var af ACIv3AttributeFilter
			if err = af.parse(trimS(sp[i])); err == nil {
				r.Push(af)
			}

		}
	}

	return err
}

/*
parseACIv3AttributeFilterOperationItem parses the string input value (raw) and attempts to marshal its contents into an instance of AttributeFilter (af). An error is returned alongside af upon completion of the attempt.
*/
func (r *ACIv3AttributeFilter) parse(raw string) (err error) {
	idx := idxr(raw, ':')
	if idx == -1 {
		err = badACIv3AFErr
		return
	}

	var at ACIv3Attribute
	if at, err = marshalACIv3Attribute(raw[:idx]); err != nil {
		return
	}

	var f Filter
	if f, err = marshalFilter(raw[idx+1:]); err == nil {
		r.Set(at, f)
	}

	return
}

/*
parseACIv3AttributeFilterOperPreamble parses the string input value (raw) and attempts to  identify the prefix as a known instance of AttributeOperation. The inferred operation identifier, which shall be either 'add=' or 'delete=' is returned as value. An error is returned alongside aop and value upon completion of the attempt.
*/
func parseACIv3AttrFilterOperPreamble(raw string) (aop ACIv3AttributeOperation, value string, err error) {
	switch {

	case hasPfx(raw, `add=`):
		aop = ACIv3AddOp
		value = raw[4:]

	case hasPfx(raw, `delete=`):
		aop = ACIv3DelOp
		value = raw[7:]

	default:
		err = badACIv3AFOpErr
	}

	return
}

//// NET

/*
ACIv3IPAddress embeds slices of address values, allowing simple composition of flexible IP-based [ACIv3BindRule] instances.
*/
type ACIv3IPAddress struct {
	*aCIIPAddresses
}

/*
IPAddress initializes, sets and returns a new instance of [ACIv3IPAddr] in one shot.
*/
func (r NetscapeACIv3) IPAddress(addr ...any) (ACIv3IPAddress, error) {
	return marshalACIv3IPAddress(addr...)
}

func marshalACIv3IPAddress(x ...any) (r ACIv3IPAddress, err error) {
	ip := new(aCIIPAddresses)
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			ip.set(tv)
		case ACIv3IPAddress:
			sp := split(tv.String(), `,`)
			ip.set(sp...)
		}
	}
	return ACIv3IPAddress{ip}, nil
}

type aCIIPAddresses []aCIIPAddress
type aCIIPAddress string

/*
Keyword returns the [ACIv3BindKeyword] instance assigned to the receiver instance as a [ACIv3Keyword]. This shall be the [ACIv3BindKeyword] that appears in a [ACIv3BindRule] containing the receiver instance as the expression value.
*/
func (r ACIv3FQDN) Keyword() ACIv3Keyword {
	return ACIv3BindDNS
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindIP] [ACIv3BindKeyword] context.
*/
func (r ACIv3IPAddress) Eq() ACIv3BindRule {
	var b ACIv3BindRule = badACIv3BindRule
	if r.Valid() == nil {
		b = newACIv3BindRuleItem(ACIv3BindIP, ACIv3Eq, r)
	}

	return b
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindIP] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3IPAddress) Ne() ACIv3BindRule {
	var b ACIv3BindRule = badACIv3BindRule
	if r.Valid() == nil {
		b = newACIv3BindRuleItem(ACIv3BindIP, ACIv3Ne, r)
	}

	return b
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus BindRule instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3IPAddress) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Len returns the integer length of the receiver instance.
*/
func (r ACIv3IPAddress) Len() int {
	var l int
	if r.aCIIPAddresses != nil {
		l = len(*r.aCIIPAddresses)
	}

	return l
}

/*
Keyword returns the [ACIv3BindKeyword] assigned to the receiver instance. This shall be the keyword that appears in a [ACIv3BindRule] containing the receiver instance as the expression value.
*/
func (r ACIv3IPAddress) Keyword() ACIv3Keyword {
	return ACIv3BindIP
}

/*
Kind returns the string representation of the receiver's kind.
*/
func (r ACIv3IPAddress) Kind() string {
	return ACIv3BindIP.String()
}

/*
Set assigns the provided address component to the receiver and returns the receiver instance in fluent-form.

Multiple values can be provided in variadic form, or piecemeal.
*/
func (r *ACIv3IPAddress) Set(addr ...string) *ACIv3IPAddress {
	if r.aCIIPAddresses == nil {
		r.aCIIPAddresses = new(aCIIPAddresses)
	}

	r.aCIIPAddresses.set(addr...)
	return r
}

func (r *aCIIPAddresses) set(addr ...string) {
	for i := 0; i < len(addr); i++ {
		if isValidIP(addr[i]) && r.unique(addr[i]) {
			*r = append(*r, aCIIPAddress(addr[i]))
		}
	}
}

func isValidIP(x string) bool {
	return isV4(x) || isV6(x)
}

func isV4(x string) bool {
	if len(x) <= 1 {
		return false
	}

	for c := 0; c < len(x); c++ {
		char := rune(byte(lc(string(x[c]))[0]))
		if !isValidV4Char(char) {
			return false
		}
	}

	return true
}

func isValidV4Char(char rune) bool {
	return ('0' <= char && char <= '9') || char == '.' || char == '*' || char == '/'
}

func isV6(x string) bool {
	if len(x) <= 1 {
		return false
	}

	for c := 0; c < len(x); c++ {
		char := rune(byte(lc(string(x[c]))[0]))
		if !isValidV6Char(char) {
			return false
		}
	}

	return true
}

func isValidV6Char(char rune) bool {
	return ('0' <= char && char <= '9') || ('a' <= char && char <= 'f') || char == ':' || char == '*' || char == '/'
}

/*
IsZero returns a Boolean value indicative of whether the receiver is considered nil, or unset.
*/
func (r ACIv3IPAddress) IsZero() bool {
	if r.aCIIPAddresses == nil {
		return true
	}

	return r.aCIIPAddresses.isZero()
}

/*
Valid returns an error indicative of whether the receiver is in an aberrant state.
*/
func (r ACIv3IPAddress) Valid() error {
	var err error
	if r.Len() == 0 {
		err = nilInstanceErr
	}

	return err
}

func (r *aCIIPAddresses) isZero() bool {
	return r == nil
}

/*
unique scans the receiver to verify whether the addr input value is not already present within the receiver.
*/
func (r ACIv3IPAddress) unique(addr string) bool {
	var b bool = true
	if !r.IsZero() {
		b = r.aCIIPAddresses.unique(addr)
	}

	return b
}

func (r aCIIPAddresses) unique(addr string) bool {
	var addrs []string
	for i := 0; i < len(r); i++ {
		addrs = append(addrs, string(r[i]))
	}

	return !strInSlice(addr, addrs)
}

/*
String returns the string representation of an IP address.
*/
func (r ACIv3IPAddress) String() string {
	var s string = badACIv3IPAddrStr
	if !r.isZero() {
		var str []string
		for i := 0; i < len(*r.aCIIPAddresses); i++ {
			str = append(str, string((*r.aCIIPAddresses)[i]))
		}
		s = join(str, `,`)
	}

	return s
}

//////////////////////////////////////////////////////////////////////////////////
// Begin DNS/FQDN
//////////////////////////////////////////////////////////////////////////////////

/*
domainLabel represents a single component within a fully-qualified domain name. Multiple occurrences of ordered instances of this type represent a complete FQDN, which may include wildcards (*), to be used in DNS-based ACIs.
*/
type domainLabel []byte
type aCIFQDNLabels []domainLabel

/*
FQDN contains ordered domain labels that form a fully-qualified domain name.
*/
type ACIv3FQDN struct {
	*aCIFQDNLabels
}

/*
DNS initializes, sets and returns a new instance of [ACIv3FQDN] in one shot.
*/
func (r NetscapeACIv3) FQDN(x ...any) (ACIv3FQDN, error) {
	return marshalACIv3FQDN(x...)
}

func marshalACIv3FQDN(x ...any) (r ACIv3FQDN, err error) {
	dns := new(aCIFQDNLabels)
	for i := 0; i < len(x); i++ {
		switch tv := x[i].(type) {
		case string:
			dns.set(tv)
		case ACIv3FQDN:
			sp := split(tv.String(), `,`)
			dns.set(sp...)
		}
	}

	r = ACIv3FQDN{dns}
	if len(x) > 0 {
		err = r.Valid()
	}

	return
}

/*
Len returns the abstract integer length of the receiver. The value returned represents the number of valid DNS labels within a given instance of [ACIv3FQDN]. For example, `www.example.com` has three (3) such labels.
*/
func (r ACIv3FQDN) Len() int {
	var l int
	if r.aCIFQDNLabels != nil {
		l = len(*r.aCIFQDNLabels)
	}

	return l
}

/*
Set appends one or more domain labels to the receiver. The total character length of a single label CANNOT exceed sixty-three (63) characters.  When added up, all domain label instances present within the receiver SHALL NOT collectively exceed two hundred fifty-three (253) characters.

Valid characters within labels:

  - a-z
  - A-Z
  - 0-9
  - Hyphen ('-', limited to [1:length-1] slice range)
  - Asterisk ('*', use with care for wildcard DNS-based ACI [ACIv3BindRule] expressions)
  - Full Stop ('.', see below for remarks on this character)

Users need not enter full stops (.) manually, given this method supports the use of variadic expressions, i.e.:

	Set(`www`,`example`,`com`)

However, should full stops (.) be used within input values:

	Set(`www.example.com`)

... the parser shall split the input into label components and add them to the receiver piecemeal in the intended order.

Please note that it is not necessary to include a NULL terminating full stop character (.) at the end (TLD?) of the intended [ACIv3FQDN].
*/
func (r *ACIv3FQDN) Set(x ...any) *ACIv3FQDN {
	if r.IsZero() {
		r.aCIFQDNLabels = new(aCIFQDNLabels)
	}

	for i := 0; i < len(x); i++ {
		if str, ok := x[i].(string); ok {
			r.aCIFQDNLabels.set(str)
		}
	}

	return r
}

func (r *aCIFQDNLabels) set(label ...string) {
	if len(label) == 0 {
		return
	}

	dl, c, ok := processLabel(label...)
	if !ok {
		return
	}

	// Only update the receiver if
	// we haven't breached the high
	// water mark ...
	if len(*r)+c <= fqdnMax {
		for l := 0; l < len(dl); l++ {
			*r = append(*r, dl[l])
		}
	}

	return
}

func processLabel(label ...string) (dl aCIFQDNLabels, c int, ok bool) {
	for i := 0; i < len(label); i++ {
		if idx := idxr(label[i], '.'); idx != -1 {
			sp := split(label[i], `.`)
			for j := 0; j < len(sp); j++ {
				// null label doesn't
				// need to stop the
				// show.
				if !validLabel(sp[j]) {
					return
				}
				c += len(sp[j])
				dl = append(dl, domainLabel(sp[j]))
			}
		} else {
			if !validLabel(label[i]) {
				return
			}
			c += len(label[i])
			dl = append(dl, domainLabel(label[i]))
		}
	}

	ok = c > 0 && len(dl) > 0
	return
}

/*
String returns the string representation of a fully-qualified domain name.
*/
func (r ACIv3FQDN) String() string {
	var s string = badACIv3FQDNStr

	if err := r.Valid(); err == nil {
		var str []string

		for i := 0; i < len(*r.aCIFQDNLabels); i++ {
			str = append(str, string((*r.aCIFQDNLabels)[i]))
		}

		s = join(str, `.`)
	}

	return s
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindDNS] [ACIv3BindKeyword] context.
*/
func (r ACIv3FQDN) Eq() ACIv3BindRule {
	if err := r.Valid(); err != nil {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(ACIv3BindDNS, ACIv3Eq, r)
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindDNS] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3FQDN) Ne() ACIv3BindRule {
	if err := r.Valid(); err != nil {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(ACIv3BindDNS, ACIv3Ne, r)
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3FQDN) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3FQDN) IsZero() bool {
	return r.aCIFQDNLabels.isZero()
}

func (r *aCIFQDNLabels) isZero() bool {
	return r == nil
}

/*
Valid returns a Boolean value indicative of whether the receiver contents represent a legal fully-qualified domain name value.
*/
func (r ACIv3FQDN) Valid() (err error) {
	L := r.len()

	if !(0 < L && L <= fqdnMax) || len(*r.aCIFQDNLabels) < 2 {
		err = badACIv3FQDNErr
	}

	// seems legit
	return
}

/*
Len returns the integer length of the receiver in terms of character count.
*/
func (r ACIv3FQDN) len() int {
	if r.aCIFQDNLabels == nil {
		return 0
	}

	var c int
	for i := 0; i < len(*r.aCIFQDNLabels); i++ {
		for j := 0; j < len(*r.aCIFQDNLabels); j++ {
			c++
		}
	}

	return c
}

/*
validLabel returns a Boolean value indicative of whether the input value (label) represents a valid label component for use within a fully-qualified domain.
*/
func validLabel(label string) bool {
	// Cannot exceed maximum component lengths!
	if !(0 < len(label) && len(label) <= labelMax) {
		return false
	}

	for i := 0; i < len(label); i++ {
		if ok := labelCharsOK(rune(label[i]), i, len(label)-1); !ok {
			return ok
		}
	}

	// seems legit
	return true
}

func labelCharsOK(c rune, i, l int) (ok bool) {
	// Cannot contain unsupported characters!
	if !isDigit(c) && !isLetter(c) &&
		c != '.' && c != '*' && c != '-' {
		return
	}

	// Cannot begin or end with hyphen!
	if c == '-' && (i == 0 || i == l) {
		return
	}

	ok = true
	return
}

//// SECURITY

/*
ACIv3AuthenticationMethod is a uint8 type that manifests through predefined package constants, each describing a supported means of LDAP authentication.
*/
type ACIv3AuthenticationMethod uint8

func (r NetscapeACIv3) AuthenticationMethod(x ...any) (ACIv3AuthenticationMethod, error) {
	return marshalACIv3AuthenticationMethod(x...)
}

/*
marshalACIv3AuthenticationMethod resolves a given authentication method based
on an integer or string input (x). If no match, an error is returned
*/
func marshalACIv3AuthenticationMethod(x ...any) (r ACIv3AuthenticationMethod, err error) {
	switch len(x) {
	case 0:
		err = badACIv3AMErr
	default:
		switch tv := x[0].(type) {
		case int:
			for k, v := range authMap {
				if k == tv {
					r = v
					break
				}
			}
		case string:
			for k, v := range authNames {
				if streqf(k, tv) {
					r = v
					break
				}
			}
		case ACIv3AuthenticationMethod:
			if err = tv.Valid(); err == nil {
				r = tv
			}
		}
	}

	return
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3AuthenticationMethod) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
	})
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindAM] [ACIv3BindKeyword] context.
*/
func (r ACIv3AuthenticationMethod) Eq() ACIv3BindRule {
	if r == noAuth {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(ACIv3BindAM, ACIv3Eq, r)
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindAM] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3AuthenticationMethod) Ne() ACIv3BindRule {
	if r == noAuth {
		return badACIv3BindRule
	}
	return newACIv3BindRuleItem(ACIv3BindAM, ACIv3Ne, r)
}

func (r ACIv3AuthenticationMethod) Valid() (err error) {
	var found bool
	for k := range authNames {
		if streqf(k, r.String()) {
			found = true
			break
		}
	}

	if !found {
		err = badACIv3AMErr
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3AuthenticationMethod) String() (am string) {
	for k, v := range authNames {
		if v == r {
			am = foldACIv3AuthenticationMethod(k)
			break
		}
	}

	return
}

/*
ACIv3SecurityStrengthFactor embeds a pointer to uint8. A nil uint8 value indicates an effective security strength factor of zero (0). A non-nil uint8 value expresses uint8 + 1, thereby allowing a range of 0-256 "within" a uint8 instance.
*/
type ACIv3SecurityStrengthFactor struct {
	*ssf
}

type ssf struct {
	*uint8
}

/*
SecurityStrengthFactor initializes, sets and returns a new instance of [ACIv3SecurityStrengthFactor] in one shot.
*/
func (r NetscapeACIv3) SecurityStrengthFactor(x ...any) (ACIv3SecurityStrengthFactor, error) {
	return marshalACIv3SecurityStrengthFactor(x...)
}

func marshalACIv3SecurityStrengthFactor(x ...any) (r ACIv3SecurityStrengthFactor, err error) {
	r = ACIv3SecurityStrengthFactor{new(ssf)}
	switch len(x) {
	case 0:
		return
	default:
		switch tv := x[0].(type) {
		case string, int:
			r.ssf.set(tv)
		case ACIv3SecurityStrengthFactor:
			r.ssf.set(tv.String())
		}
	}

	err = r.Valid()

	return
}

/*
Keyword returns the BindKeyword assigned to the receiver instance enveloped as a [ACIv3Keyword]. This shall be the keyword that appears in a [ACIv3BindRule] containing the receiver instance as the expression value.
*/
func (r ACIv3SecurityStrengthFactor) Keyword() ACIv3Keyword {
	return ACIv3BindSSF
}

/*
IsZero returns a Boolean value indicative of whether the receiver is nil, or unset.
*/
func (r ACIv3SecurityStrengthFactor) IsZero() bool {
	if r.ssf == nil {
		return true
	}

	return r.uint8 == nil
}

/*
Eq initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Equal-To the [ACIv3BindSSF] [ACIv3BindKeyword] context.
*/
func (r ACIv3SecurityStrengthFactor) Eq() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Eq, r)
}

/*
Ne initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Not-Equal-To the [ACIv3BindSSF] [ACIv3BindKeyword] context.

Negated equality [ACIv3BindRule] instances should be used with caution.
*/
func (r ACIv3SecurityStrengthFactor) Ne() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Ne, r)
}

/*
Lt initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Less-Than the [ACIv3BindSSF] [ACIv3BindKeyword] context.
*/
func (r ACIv3SecurityStrengthFactor) Lt() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Lt, r)
}

/*
Le initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Less-Than-Or-Equal to the [ACIv3BindSSF] [ACIv3BindKeyword] context.
*/
func (r ACIv3SecurityStrengthFactor) Le() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Le, r)
}

/*
Gt initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Greater-Than the [ACIv3BindSSF] [ACIv3BindKeyword] context.
*/
func (r ACIv3SecurityStrengthFactor) Gt() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Gt, r)
}

/*
Ge initializes and returns a new [ACIv3BindRule] instance configured to express the evaluation of the receiver value as Greater-Than-Or-Equal to the [ACIv3BindSSF] [ACIv3BindKeyword] context.
*/
func (r ACIv3SecurityStrengthFactor) Ge() ACIv3BindRule {
	return newACIv3BindRuleItem(ACIv3BindSSF, ACIv3Ge, r)
}

/*
BRM returns an instance of [ACIv3BindRuleMethods].

Each of the return instance's key values represent a single instance of the [ACIv3Operator] type that is allowed for use in the creation of [ACIv3BindRule] instances which bear the receiver instance as an expression value. The value for each key is the actual [ACIv3BindRuleMethod] instance for OPTIONAL use in the creation of a [ACIv3BindRule] instance.

This is merely a convenient alternative to maintaining knowledge of which [ACIv3Operator] instances apply to which types. Instances of this type are also used to streamline package unit tests.

Please note that if the receiver is in an aberrant state, or if it has not yet been initialized, the execution of ANY of the return instance's value methods will return bogus [ACIv3BindRule] instances. While this is useful in unit testing, the end user must only execute this method IF and WHEN the receiver has been properly populated and prepared for such activity.
*/
func (r ACIv3SecurityStrengthFactor) BRM() ACIv3BindRuleMethods {
	return newACIv3BindRuleMethods(aCIBindRuleFuncMap{
		ACIv3Eq: r.Eq,
		ACIv3Ne: r.Ne,
		ACIv3Lt: r.Lt,
		ACIv3Le: r.Le,
		ACIv3Gt: r.Gt,
		ACIv3Ge: r.Ge,
	})
}

/*
String returns the string representation of the receiver instance.
*/
func (r ACIv3SecurityStrengthFactor) String() string {
	var s string = `0`
	if !r.IsZero() {
		s = itoa(int((*r.ssf.uint8)) + 1)
	}

	return s
}

/*
Valid returns nil and, at present, does nothing else. Based on the efficient design of the receiver type, there is no possible state that is technically invalid at ALL times. A nil instance may, in fact, be correct in particular situations.

Thus as there is no room for unforeseen errors with regards to this type specifically, this method has been gutted but remains present merely for the purpose of signature consistency throughout the package.
*/
func (r ACIv3SecurityStrengthFactor) Valid() error { return nil }

func (r ACIv3SecurityStrengthFactor) clear() {
	if !r.IsZero() {
		r.ssf.clear()
	}
}

func (r *ssf) clear() {
	if r != nil {
		r.uint8 = nil
	}
}

/*
Set modifies the receiver to reflect the desired security strength factor (SSF), which can represent any numerical value between 0 (off) and 256 (max).

Valid input types are int, string and nil.

A value of nil wipes out any previous value, making the SSF effectively zero (0).

A string value of `full` or `max` sets the SSF to its maximum value. A value of `none` or `off` has the same effect as when providing a nil value. A numerical string value is cast as int and (if valid) will be resubmitted silently. Case is not significant during the string matching process.

An int value less than or equal to zero (0) has the same effect as when providing a nil value. A value between 1 and 256 is acceptable and will be used. A value greater than 256 will be silently reduced back to the maximum.
*/
func (r *ACIv3SecurityStrengthFactor) Set(factor any) ACIv3SecurityStrengthFactor {
	if r.ssf == nil {
		r.ssf = new(ssf)
		r.ssf.uint8 = new(uint8)
	}
	r.ssf.set(factor)
	return *r
}

/*
set is called by [ACIv3SecurityStrengthFactor.Set] to modify the underlying uint8 pointer in order to represent a security strength factor value.
*/
func (r *ssf) set(factor any) {
	switch tv := factor.(type) {
	case nil:
		r.clear()
	case string:
		i := stringToIntSSF(tv)
		if i == 0 {
			r.clear()
			return
		}
		r.set(i)
	case int:
		if tv > 256 {
			tv = 256
		} else if tv <= 0 {
			r.clear()
			return
		}

		v := uint8(tv - 1)
		r.uint8 = &v
	}

	return
}

func stringToIntSSF(x string) (i int) {
	switch lc(x) {
	case `full`, `max`:
		i = 256
	case `none`, `off`:
		i = 0
	default:
		i, _ = atoi(x)
	}

	return
}

/*
foldACIv3AuthenticationMethod executes the string representation case-folding, per whatever value is assigned to the global ACIv3AuthenticationMethodLowerCase variable.
*/
func foldACIv3AuthenticationMethod(x string) string {
	if ACIv3AuthenticationMethodLowerCase {
		return lc(x)
	}
	return uc(x)
}

func init() {
	aCIRightsMap = map[ACIv3Right]string{
		ACIv3NoAccess:        `none`,
		ACIv3ReadAccess:      `read`,
		ACIv3WriteAccess:     `write`,
		ACIv3AddAccess:       `add`,
		ACIv3DeleteAccess:    `delete`,
		ACIv3SearchAccess:    `search`,
		ACIv3CompareAccess:   `compare`,
		ACIv3SelfWriteAccess: `selfwrite`,
		ACIv3AllAccess:       `all`,
		ACIv3ProxyAccess:     `proxy`,
		ACIv3ImportAccess:    `import`,
		ACIv3ExportAccess:    `export`,
	}

	// we want to resolve the *name*
	// of an ACIv3Right into an actual
	// ACIv3Right instance.
	aCIRightsNames = make(map[string]ACIv3Right, 0)
	for k, v := range aCIRightsMap {
		aCIRightsNames[v] = k
	}

	aCILevelMap = map[int]ACIv3InheritanceLevel{
		0: ACIv3Level0,
		1: ACIv3Level1,
		2: ACIv3Level2,
		3: ACIv3Level3,
		4: ACIv3Level4,
		5: ACIv3Level5,
		6: ACIv3Level6,
		7: ACIv3Level7,
		8: ACIv3Level8,
		9: ACIv3Level9,
	}

	aCILevelNumbers = map[string]ACIv3InheritanceLevel{
		`0`: ACIv3Level0,
		`1`: ACIv3Level1,
		`2`: ACIv3Level2,
		`3`: ACIv3Level3,
		`4`: ACIv3Level4,
		`5`: ACIv3Level5,
		`6`: ACIv3Level6,
		`7`: ACIv3Level7,
		`8`: ACIv3Level8,
		`9`: ACIv3Level9,
	}

	aCIOperatorMap = map[string]ACIv3Operator{
		ACIv3Eq.String(): ACIv3Eq,
		ACIv3Ne.String(): ACIv3Ne,
		ACIv3Lt.String(): ACIv3Lt,
		ACIv3Le.String(): ACIv3Le,
		ACIv3Gt.String(): ACIv3Gt,
		ACIv3Ge.String(): ACIv3Ge,
	}

	// populate the allowed comparison operator map per each
	// possible ACIv3TargetRule keyword
	aCIPermittedTargetOperators = map[ACIv3Keyword][]ACIv3Operator{
		ACIv3Target:            {ACIv3Eq, ACIv3Ne},
		ACIv3TargetTo:          {ACIv3Eq, ACIv3Ne},
		ACIv3TargetFrom:        {ACIv3Eq, ACIv3Ne},
		ACIv3TargetCtrl:        {ACIv3Eq, ACIv3Ne},
		ACIv3TargetAttr:        {ACIv3Eq, ACIv3Ne},
		ACIv3TargetExtOp:       {ACIv3Eq, ACIv3Ne},
		ACIv3TargetScope:       {ACIv3Eq},
		ACIv3TargetFilter:      {ACIv3Eq, ACIv3Ne},
		ACIv3TargetAttrFilters: {ACIv3Eq},
	}

	// populate the allowed comparison operator map per each
	// possible ACIv3BindRule keyword
	aCIPermittedBindOperators = map[ACIv3Keyword][]ACIv3Operator{
		ACIv3BindUDN: {ACIv3Eq, ACIv3Ne},
		ACIv3BindRDN: {ACIv3Eq, ACIv3Ne},
		ACIv3BindGDN: {ACIv3Eq, ACIv3Ne},
		ACIv3BindIP:  {ACIv3Eq, ACIv3Ne},
		ACIv3BindAM:  {ACIv3Eq, ACIv3Ne},
		ACIv3BindDNS: {ACIv3Eq, ACIv3Ne},
		ACIv3BindUAT: {ACIv3Eq, ACIv3Ne},
		ACIv3BindGAT: {ACIv3Eq, ACIv3Ne},
		ACIv3BindDoW: {ACIv3Eq, ACIv3Ne},
		ACIv3BindSSF: {ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Le, ACIv3Gt, ACIv3Ge},
		ACIv3BindToD: {ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Le, ACIv3Gt, ACIv3Ge},
	}

	// bindkeyword map
	aCIBindKeywordMap = map[ACIv3Keyword]string{
		ACIv3BindUDN: `userdn`,
		ACIv3BindRDN: `roledn`,
		ACIv3BindGDN: `groupdn`,
		ACIv3BindUAT: `userattr`,
		ACIv3BindGAT: `groupattr`,
		ACIv3BindIP:  `ip`,
		ACIv3BindDNS: `dns`,
		ACIv3BindDoW: `dayofweek`,
		ACIv3BindToD: `timeofday`,
		ACIv3BindAM:  `authmethod`,
		ACIv3BindSSF: `ssf`,
	}

	// targetkeyword map
	aCITargetKeywordMap = map[ACIv3Keyword]string{
		ACIv3Target:            `target`,
		ACIv3TargetTo:          `target_to`,
		ACIv3TargetAttr:        `targetattr`,
		ACIv3TargetCtrl:        `targetcontrol`,
		ACIv3TargetFrom:        `target_from`,
		ACIv3TargetScope:       `targetscope`,
		ACIv3TargetFilter:      `targetfilter`,
		ACIv3TargetAttrFilters: `targattrfilters`,
		ACIv3TargetExtOp:       `extop`,
	}

	// bindtype map
	aCIBTMap = map[ACIv3BindType]string{
		ACIv3BindTypeUSERDN:  `USERDN`,
		ACIv3BindTypeROLEDN:  `ROLEDN`,
		ACIv3BindTypeSELFDN:  `SELFDN`,
		ACIv3BindTypeGROUPDN: `GROUPDN`,
		ACIv3BindTypeLDAPURL: `LDAPURL`,
	}

	// authMap facilitates lookups of ACIv3AuthenticationMethod
	// instances using their underlying numerical const
	// value; this is mostly used internally.
	authMap = map[int]ACIv3AuthenticationMethod{
		0: ACIv3Anonymous,
		1: ACIv3Simple,
		2: ACIv3SSL,
		3: ACIv3SASL,
		4: ACIv3DIGESTMD5,
		5: ACIv3EXTERNAL,
		6: ACIv3GSSAPI,
	}

	// authNames facilities lookups of ACIv3AuthenticationMethod
	// instances using their string representation. as the
	// lookup key.
	//
	// NOTE: case is not significant during string
	// *matching* (resolution); this is regardless
	// of the state of ACIv3AuthenticationMethodLowerCase.
	authNames = map[string]ACIv3AuthenticationMethod{
		`none`:   ACIv3Anonymous, // anonymous is ALWAYS default
		`simple`: ACIv3Simple,    // simple auth (DN + Password); no confidentiality is implied
		`ssl`:    ACIv3SSL,       // authentication w/ confidentiality; SSL (LDAPS) and TLS (LDAP + STARTTLS)

		// NOTE: Supported SASL methods vary per impl.
		`sasl`:            ACIv3SASL,      // *any* SASL mechanism
		`sasl EXTERNAL`:   ACIv3EXTERNAL,  // only SASL/EXTERNAL mechanism, e.g.: TLS Client Auth w/ personal cert
		`sasl DIGEST-MD5`: ACIv3DIGESTMD5, // only SASL/DIGEST-MD5 mechanism, e.g.: password encipherment
		`sasl GSSAPI`:     ACIv3GSSAPI,    // only SASL/GSSAPI mechanism, e.g.: Kerberos Single Sign-On
	}
}
