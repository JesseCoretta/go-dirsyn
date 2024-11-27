package dirsyn

import "sync"

/*
schema.go implements much of Section 4 of RFC 4512.
*/

/*
NewSubschemaSubentry returns a freshly initialized instance of
*[SubschemaSubentry].
*/
func NewSubschemaSubentry() *SubschemaSubentry {
	sch := &SubschemaSubentry{
		lock: &sync.Mutex{},
	}
	sch.primeBuiltIns()
	return sch
}

/*
Definition is an interface type qualified through instances of the
following types:

  - [LDAPSyntaxDescription]
  - [MatchingRuleDescription]
  - [AttributeTypeDescription]
  - [MatchingRuleUseDescription]
  - [ObjectClassDescription]
  - [DITContentRuleDescription]
  - [NameFormDescription]
  - [DITStructureRuleDescription]
*/
type Definition interface {
	OID() string
	Type() string
	String() string
	isDefinition()
}

/*
Definitions is an interface type qualified through instances of the
following types:

  - [LDAPSyntaxes]
  - [MatchingRules]
  - [AttributeTypes]
  - [MatchingRuleUse]
  - [ObjectClasses]
  - [DITContentRules]
  - [NameForms]
  - [DITStructureRules]
*/
type Definitions interface {
	Len() int
	OID() string
	Type() string
	String() string
	Contains(string) int
	isDefinitions()
}

/*
SubschemaSubentry implements [§ 4.2 of RFC 4512] and contains slice types
of various definition types.

[§ 4.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2
*/
type SubschemaSubentry struct {
	LDAPSyntaxes
	MatchingRules
	AttributeTypes
	MatchingRuleUse
	ObjectClasses
	DITContentRules
	NameForms
	DITStructureRules

	lock *sync.Mutex
}

func (r *SubschemaSubentry) primeBuiltIns() {
	for _, slice := range primerSyntaxes {
		if err := r.RegisterLDAPSyntax(slice); err != nil {
			panic(err)
		}
	}
	for _, slice := range primerMatchingRules {
		if err := r.RegisterMatchingRule(slice); err != nil {
			panic(err)
		}
	}
}

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r SubschemaSubentry) OID() string { return `2.5.18.10` }

/*
String returns the string representation of the receiver instance.
*/
func (r SubschemaSubentry) String() (ssse string) {

	ssse += r.LDAPSyntaxes.String()
	ssse += r.MatchingRules.String()
	ssse += r.AttributeTypes.String()
	ssse += r.MatchingRuleUse.String()
	ssse += r.ObjectClasses.String()
	ssse += r.DITContentRules.String()
	ssse += r.NameForms.String()
	ssse += r.DITStructureRules.String()

	// remove final newline
	ssse = trim(ssse, string(rune(10)))

	return
}

/*
Push assigns def to the receiver instance. This method engages [sync.Lock]
and is thread-safe.

The input def argument must be one of the following types:

  - [LDAPSyntaxDescription]
  - [MatchingRuleDescription]
  - [AttributeTypeDescription]
  - [ObjectClassDescription]
  - [DITContentRuleDescription]
  - [NameFormDescription]
  - [DITStructureRuleDescription]
*/
func (r *SubschemaSubentry) Push(def any) {
	switch tv := def.(type) {
	case LDAPSyntaxDescription:
		r.RegisterLDAPSyntax(tv)
	case MatchingRuleDescription:
		r.RegisterMatchingRule(tv)
	case AttributeTypeDescription:
		r.RegisterAttributeType(tv)
	case ObjectClassDescription:
		r.RegisterObjectClass(tv)
	case DITContentRuleDescription:
		r.RegisterDITContentRule(tv)
	case NameFormDescription:
		r.RegisterNameForm(tv)
	case DITStructureRuleDescription:
		r.RegisterDITStructureRule(tv)
	}
}

/*
RegisterLDAPSyntax returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [LDAPSyntaxDescription], or its
equivalent string representation as described in [§ 4.1.5 of RFC 4512].

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
func (r *SubschemaSubentry) RegisterLDAPSyntax(input any) (err error) {
	var def LDAPSyntaxDescription

	switch tv := input.(type) {
	case LDAPSyntaxDescription:
		if !def.Valid() {
			err = errorTxt("ldapSyntax: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalLDAPSyntaxDescription(tv)
	default:
		err = errorBadType("LDAPSyntaxDescription")
	}

	if err != nil {
		return
	}

	if r.LDAPSyntaxes.Contains(def.NumericOID) != -1 {
		err = errorTxt("ldapSyntax: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.LDAPSyntaxes = append(r.LDAPSyntaxes, def)

	return
}

/*
RegisterMatchingRule returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [MatchingRuleDescription], or its
equivalent string representation as described in [§ 4.1.3 of RFC 4512].

[§ 4.1.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3
*/
func (r *SubschemaSubentry) RegisterMatchingRule(input any) (err error) {
	var def MatchingRuleDescription

	switch tv := input.(type) {
	case MatchingRuleDescription:
		if !def.Valid() {
			err = errorTxt("matchingRule: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalMatchingRuleDescription(tv)
	default:
		err = errorBadType("MatchingRuleDescription")
	}

	if err != nil {
		return
	}

	if len(def.Syntax) > 0 {
		if r.LDAPSyntaxes.Contains(def.Syntax) == -1 {
			err = errorTxt("matchingRule: Unknown SYNTAX '" + def.Syntax + "'")
			return
		}
	}

	if r.MatchingRules.Contains(def.NumericOID) != -1 {
		err = errorTxt("matchingRule: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.MatchingRules = append(r.MatchingRules, def)

	return
}

/*
RegisterAttributeType returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [AttributeTypeDescription], or its
equivalent string representation as described in [§ 4.1.2 of RFC 4512].

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
*/
func (r *SubschemaSubentry) RegisterAttributeType(input any) (err error) {
	var def AttributeTypeDescription

	switch tv := input.(type) {
	case AttributeTypeDescription:
		if !def.Valid() {
			err = errorTxt("attributeType: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalAttributeTypeDescription(tv)
	default:
		err = errorBadType("AttributeTypeDescription")
	}

	if err != nil {
		return
	}

	if r.AttributeTypes.Contains(def.NumericOID) != -1 {
		err = errorTxt("attributeType: Duplicate registration: '" +
			def.NumericOID + "'")
		return
	}

	for typ, mr := range map[string]string{
		"EQUALITY": def.Equality,
		"ORDERING": def.Ordering,
		"SUBSTR":   def.Substring,
	} {
		if mr != "" {
			if r.MatchingRules.Contains(mr) == -1 {
				err = errorTxt("attributeType: Unknown " + typ +
					" matching rule: '" + mr + "'")
				return
			}
		}
	}

	// Make sure supertype, if present, is sane.
	if def.SuperType != "" {
		if r.AttributeTypes.Contains(def.SuperType) == -1 {
			err = errorTxt("attributeType: Unknown SUP (supertype): '" +
				def.SuperType + "'")
			return
		}
	}

	if len(def.Syntax) > 0 {
		if r.LDAPSyntaxes.Contains(def.Syntax) == -1 {
			err = errorTxt("attributeType: Unknown SYNTAX '" + def.Syntax + "'")
			return
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.AttributeTypes = append(r.AttributeTypes, def)

	return
}

/*
RegisterObjectClass returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [ObjectClassDescription], or its
equivalent string representation as described in [§ 4.1.1 of RFC 4512].

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
func (r *SubschemaSubentry) RegisterObjectClass(input any) (err error) {
	var def ObjectClassDescription

	switch tv := input.(type) {
	case ObjectClassDescription:
		if !def.Valid() {
			err = errorTxt("objectClass: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalObjectClassDescription(tv)
	default:
		err = errorBadType("ObjectClassDescription")
	}

	if err != nil {
		return
	}

	if r.ObjectClasses.Contains(def.NumericOID) != -1 {
		err = errorTxt("objectClass: Duplicate registration: '" +
			def.NumericOID + "'")
		return
	}

	// Verify MANDATORY / PERMITTED types
	for clause, slices := range map[string][]string{
		`MUST`: def.Must,
		`MAY`:  def.May,
	} {
		for _, at := range slices {
			if r.AttributeTypes.Contains(at) == -1 {
				err = errorTxt("objectClass: Unknown " + clause +
					" attribute type: '" + at + "'")
			}
		}
	}

	// Make sure superclasses, if present, are sane.
	for i := 0; i < len(def.SuperClasses); i++ {
		if r.ObjectClasses.Contains(def.SuperClasses[i]) == -1 {
			err = errorTxt("objectClass: Unknown SUP (superclass): '" +
				def.SuperClasses[i] + "'")
			return
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.ObjectClasses = append(r.ObjectClasses, def)

	return
}

/*
RegisterDITContentRule returns an error following an attempt to add a new
[DITContentRuleDescription] to the receiver instance.

Valid input types may be an instance of [DITContentRuleDescription], or its
equivalent string representation as described in [§ 4.1.6 of RFC 4512].

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
func (r *SubschemaSubentry) RegisterDITContentRule(input any) (err error) {
	var def DITContentRuleDescription

	switch tv := input.(type) {
	case DITContentRuleDescription:
		if !def.Valid() {
			err = errorTxt("dITContentRule: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalDITContentRuleDescription(tv)
	default:
		err = errorBadType("DITContentRuleDescription")
	}

	if err != nil {
		return
	}

	if r.ObjectClasses.Contains(def.NumericOID) == -1 {
		err = errorTxt("dITContentRule: Unregistered structural class OID: '" +
			def.NumericOID + "'")
		return
	} else if r.DITContentRules.Contains(def.NumericOID) != -1 {
		err = errorTxt("dITContentRule: Duplicate registration: '" +
			def.NumericOID + "'")
		return
	}

	// Verify MANDATORY / PERMITTED / PROHIBITED types
	for clause, slices := range map[string][]string{
		`MUST`: def.Must,
		`MAY`:  def.May,
		`NOT`:  def.Not,
	} {
		for _, at := range slices {
			if r.AttributeTypes.Contains(at) == -1 {
				err = errorTxt("dITContentRule: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	// Make sure auxiliary classes, if present, are sane.
	for i := 0; i < len(def.Aux); i++ {
		if idx := r.ObjectClasses.Contains(def.Aux[i]); idx == -1 {
			err = errorTxt("dITContentRule: Unknown AUX (auxiliary class): '" +
				def.Aux[i] + "'")
			return
		} else if r.ObjectClasses[idx].Kind != 1 {
			err = errorTxt("dITContentRule: non-AUX class in AUX clause")
			return
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.DITContentRules = append(r.DITContentRules, def)

	return
}

/*
RegisterNameForm returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [NameFormDescription], or its
equivalent string representation as described in [§ 4.1.7.2 of RFC 4512].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
func (r *SubschemaSubentry) RegisterNameForm(input any) (err error) {
	var def NameFormDescription

	switch tv := input.(type) {
	case NameFormDescription:
		if !def.Valid() {
			err = errorTxt("nameForm: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalNameFormDescription(tv)
	default:
		err = errorBadType("NameFormDescription")
	}

	if err != nil {
		return
	}

	if r.ObjectClasses.Contains(def.OC) == -1 {
		err = errorTxt("nameForm: Unknown structural class OID: '" +
			def.OC + "'")
		return
	} else if r.NameForms.Contains(def.NumericOID) != -1 {
		err = errorTxt("nameForm: Duplicate registration: '" +
			def.NumericOID + "'")
		return
	}

	// Verify MANDATORY / PERMITTED types
	for clause, slices := range map[string][]string{
		`MUST`: def.Must,
		`MAY`:  def.May,
	} {
		for _, at := range slices {
			if r.AttributeTypes.Contains(at) == -1 {
				err = errorTxt("nameForm: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.NameForms = append(r.NameForms, def)

	return
}

/*
RegisterDITStructureRule returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [DITStructureRuleDescription], or its
equivalent string representation as described in [§ 4.1.7.1 of RFC 4512].

[§ 4.1.7.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1
*/
func (r *SubschemaSubentry) RegisterDITStructureRule(input any) (err error) {
	var def DITStructureRuleDescription

	switch tv := input.(type) {
	case DITStructureRuleDescription:
		if !def.Valid() {
			err = errorTxt("dITStructureRule: Invalid description syntax")
		}
		def = tv
	case string:
		def, err = marshalDITStructureRuleDescription(tv)
	default:
		err = errorBadType("DITStructureRuleDescription")
	}

	if err != nil {
		return
	}

	if r.DITStructureRules.Contains(def.RuleID) != -1 {
		err = errorTxt("dITStructureRule: Duplicate registration: '" +
			def.RuleID + "'")
		return
	} else if r.NameForms.Contains(def.Form) == -1 {
		err = errorTxt("dITStructureRule: nameForm: Unknown name form OID: '" +
			def.Form + "'")
		return
	}

	// Make sure superclasses, if present, are sane.
	for i := 0; i < len(def.SuperRules); i++ {
		if r.DITStructureRules.Contains(def.SuperRules[i]) == -1 {
			// Allow recursive rules to be added (ignore
			// "Not Found" for current ruleid).
			if def.SuperRules[i] != def.RuleID {
				err = errorTxt("dITStructureRule: Unknown SUP (superior rule): '" +
					def.SuperRules[i] + "'")
				return
			}
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.DITStructureRules = append(r.DITStructureRules, def)

	return
}

/*
Counters returns an instance of [9]int, each slice representing the
current number of definitions of a particular collection, while the
final slice represents the total of the previous eight (8).

Collection indices are as follows:

  - 0 - "ldapSyntaxes"
  - 1 - "matchingRules"
  - 2 - "attributeTypes"
  - 3 - "matchingRuleUses"
  - 4 - "objectClasses"
  - 5 - "dITContentRules"
  - 6 - "nameForms"
  - 7 - "dITStructureRules"
  - 8 - "total"
*/
func (r SubschemaSubentry) Counters() (counters [9]int) {
	counters[0] = len(r.LDAPSyntaxes)
	counters[1] = len(r.MatchingRules)
	counters[2] = len(r.AttributeTypes)
	counters[3] = len(r.MatchingRuleUse)
	counters[4] = len(r.ObjectClasses)
	counters[5] = len(r.DITContentRules)
	counters[6] = len(r.NameForms)
	counters[7] = len(r.DITStructureRules)
	counters[8] = counters[0] +
		counters[1] +
		counters[2] +
		counters[3] +
		counters[4] +
		counters[5] +
		counters[6] +
		counters[7]

	return
}

/*
Extension implements [§ 4.2 of RFC 4512] and describes a single extension
using an "xstring" and one or more quoted string values.

[§ 4.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2
*/
type Extension struct {
	XString string
	Values  []string
}

/*
String returns the string representation of the receiver instance.
*/
func (r Extension) String() (ext string) {
	if len(r.XString) > 0 && len(r.Values) > 0 {
		ext = ` ` + r.XString + ` ` + stringQuotedDescrs(r.Values)
	}

	return
}

/*
LDAPSyntaxes implements [§ 4.2.5 of RFC 4512] and contains slices of
[LDAPSyntaxDescription].

[§ 4.2.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.5
*/
type LDAPSyntaxes []LDAPSyntaxDescription

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntaxes) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or DESC clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r LDAPSyntaxes) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		desc := repAll(r[i].Description, ` `, ``)
		fn := streqf(id, desc)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r LDAPSyntaxes) OID() string { return `1.3.6.1.4.1.1466.101.120.16` }

/*
LDAPSyntaxDescription implements [§ 4.1.5 of RFC 4512].

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
type LDAPSyntaxDescription struct {
	NumericOID  string // IDENTIFIER
	Description string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntaxDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
xPattern returns the regular expression statement assigned to the receiver.
This will be used by [LDAPSyntaxDescription.Verify] method to validate a
value against a custom syntax.
*/
func (r LDAPSyntaxDescription) xPattern() (xpat string) {
	for _, v := range r.Extensions {
		if v.XString == `X-PATTERN` && len(v.Values) > 0 {
			xpat = v.Values[0]
			break
		}
	}

	return
}

/*
Verify returns an instance of [Boolean] following an analysis of input
value x against the underlying syntax.

Not to be confused with [LDAPSyntaxDescription.Valid] which only checks
the validity of a syntax definition itself -- not a value.
*/
func (r LDAPSyntaxDescription) Verify(x any) (result Boolean) {
	if xpat := r.xPattern(); xpat != "" {
		if assert, err := assertString(x, 0, "X-PATTERN"); err == nil {
			var match bool
			if match, err = regexMatch(xpat, assert); err == nil {
				result.Set(match)
			}
		}
	} else {
		if funk, found := syntaxVerifiers[r.NumericOID]; found {
			result = funk(x)
		}
	}

	return
}

/*
Valid returns a Boolean value indicative of a valid receiver instance.
*/
func (r LDAPSyntaxDescription) Valid() bool {
	return len(r.NumericOID) > 0
}

/*
MatchingRules implements [§ 4.2.3 of RFC 4512] and contains slices of
[MatchingRuleDescription].

[§ 4.2.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.3
*/
type MatchingRules []MatchingRuleDescription

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r MatchingRules) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r MatchingRules) OID() string { return `2.5.21.4` }

/*
MatchingRuleDescription implements [§ 4.1.3 of RFC 4512].

[§ 4.1.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3
*/
type MatchingRuleDescription struct {
	NumericOID  string
	Name        []string
	Description string
	Obsolete    bool
	Syntax      string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}
		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += ` SYNTAX ` + r.Syntax
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleDescription) Valid() bool {
	return len(r.NumericOID) > 0 &&
		len(r.Syntax) > 0
}

/*
AttributeTypes implements [§ 4.2.2 of RFC 4512] and contains slices of
[AttributeTypeDescription].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
*/
type AttributeTypes []AttributeTypeDescription

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r AttributeTypes) OID() string { return `2.5.21.5` }

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypes) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r AttributeTypes) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
AttributeTypeDescription implements [§ 4.1.2 of RFC 4512].

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
*/
type AttributeTypeDescription struct {
	NumericOID         string
	Name               []string
	Description        string
	SuperType          string
	Obsolete           bool
	Single             bool
	Collective         bool
	NoUserModification bool
	MinUpperBounds     uint
	Syntax             string
	Equality           string
	Ordering           string
	Substring          string
	Usage              string
	Extensions         map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypeDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}

		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}

		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)

		if len(r.SuperType) > 0 {
			def += ` SUP ` + r.SuperType
		}

		def += r.syntaxMatchingRuleClauses()
		def += r.mutexBooleanString()
		def += stringBooleanClause(`NO-USER-MODIFICATION`, r.NoUserModification)

		if len(r.Usage) > 0 && lc(r.Usage) != "userapplications" {
			def += ` USAGE ` + r.Usage
		}
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

func (r AttributeTypeDescription) mutexBooleanString() (clause string) {
	if r.Single {
		clause += ` SINGLE-VALUE`
	} else if r.Collective {
		clause += ` COLLECTIVE`
	}

	return
}

func (r AttributeTypeDescription) syntaxMatchingRuleClauses() (clause string) {
	if len(r.Equality) > 0 {
		clause += ` EQUALITY ` + r.Equality
	}

	if len(r.Ordering) > 0 {
		clause += ` ORDERING ` + r.Ordering
	}

	if len(r.Substring) > 0 {
		clause += ` SUBSTR ` + r.Substring
	}

	if len(r.Syntax) > 0 {
		clause += ` SYNTAX ` + r.Syntax
		if r.MinUpperBounds > 0 {
			clause += `{` + fuint(uint64(r.MinUpperBounds), 10) + `}`
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypeDescription) Valid() bool {
	return len(r.NumericOID) > 0 &&
		!(r.Collective && r.Single) &&
		(len(r.SuperType) > 0 || len(r.Syntax) > 0)
}

/*
MatchingRuleUse implements [§ 4.2.4 of RFC 4512] and contains slices of
[MatchingRuleUseDescription].

[§ 4.2.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.4
*/
type MatchingRuleUse []MatchingRuleUseDescription

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUse) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r MatchingRuleUse) OID() string { return `2.5.21.8` }

/*
MatchingRuleUseDescription implements [§ 4.1.4 of RFC 4512].

[§ 4.1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.4
*/
type MatchingRuleUseDescription struct {
	NumericOID  string
	Name        []string
	Description string
	Obsolete    bool
	Applies     []string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUseDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}
		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += ` APPLIES ` + stringDescrs(r.Applies, ` $ `)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUseDescription) Valid() bool {
	return len(r.NumericOID) > 0 &&
		len(r.Applies) > 0
}

/*
ObjectClasses implements [§ 4.2.1 of RFC 4512] and contains slices of
[ObjectClassDescription].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
type ObjectClasses []ObjectClassDescription

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r ObjectClasses) OID() string { return `2.5.21.6` }

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r ObjectClasses) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectClasses) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
ObjectClassDescription implements [§ 4.1.1 of RFC 4512].

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
type ObjectClassDescription struct {
	NumericOID   string
	Name         []string
	Description  string
	Obsolete     bool
	Kind         uint8 // 0=STRUCTURAL/1=AUXILIARY/2=ABSTRACT; DEFAULT=0
	SuperClasses []string
	Must         []string
	May          []string
	Extensions   map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectClassDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}

		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}

		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)

		if len(r.SuperClasses) > 0 {
			def += ` SUP ` + stringDescrs(r.SuperClasses, ` $ `)
		}

		def += stringClassKind(r.Kind)

		if len(r.Must) > 0 {
			def += ` MUST ` + stringDescrs(r.Must, ` $ `)
		}

		if len(r.May) > 0 {
			def += ` MAY ` + stringDescrs(r.May, ` $ `)
		}

		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

func stringClassKind(kind uint8) (k string) {
	if 0 <= kind && kind <= 2 {
		if kind == 1 {
			k = ` AUXILIARY`
		} else if kind == 2 {
			k = ` ABSTRACT`
		} else {
			k = ` STRUCTURAL`
		}
	} else {
		k = ` STRUCTURAL`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectClassDescription) Valid() bool {
	return len(r.NumericOID) > 0
}

/*
DITContentRules implements [§ 4.2.6 of RFC 4512] and contains slices of
[DITContentRuleDescription].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
type DITContentRules []DITContentRuleDescription

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r DITContentRules) OID() string { return `2.5.21.2` }

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r DITContentRules) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITContentRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
DITContentRuleDescription implements [§ 4.1.6 of RFC 4512].

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
type DITContentRuleDescription struct {
	NumericOID  string
	Name        []string
	Description string
	Obsolete    bool
	Aux         []string
	Must        []string
	May         []string
	Not         []string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITContentRuleDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}

		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}

		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)

		if len(r.Aux) > 0 {
			def += ` AUX ` + stringDescrs(r.Aux, ` $ `)
		}

		if len(r.Must) > 0 {
			def += ` MUST ` + stringDescrs(r.Must, ` $ `)
		}

		if len(r.May) > 0 {
			def += ` MAY ` + stringDescrs(r.May, ` $ `)
		}

		if len(r.Not) > 0 {
			def += ` NOT ` + stringDescrs(r.Not, ` $ `)
		}

		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITContentRuleDescription) Valid() bool {
	return len(r.NumericOID) > 0
}

/*
NameForms implements [§ 4.2.8 of RFC 4512] and contains slices of
[NameFormDescription].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
type NameForms []NameFormDescription

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r NameForms) OID() string { return `2.5.21.7` }

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r NameForms) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].NumericOID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r NameForms) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
NameFormDescription implements [§ 4.1.7.2 of RFC 4512].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
type NameFormDescription struct {
	NumericOID  string
	Name        []string
	Description string
	Obsolete    bool
	OC          string
	Must        []string
	May         []string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r NameFormDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}
		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}

		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += ` OC ` + r.OC
		def += ` MUST ` + stringDescrs(r.Must, ` $ `)
		if len(r.May) > 0 {
			def += ` MAY ` + stringDescrs(r.May, ` $ `)
		}
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r NameFormDescription) Valid() bool {
	return len(r.NumericOID) > 0 && len(r.OC) > 0 && len(r.Must) > 0
}

/*
DITStructureRules implements [§ 4.2.7 of RFC 4512] and contains slices of
[DITStructureRuleDescription].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
type DITStructureRules []DITStructureRuleDescription

/*
OID returns the numeric OID associated with the receiver instance.
*/
func (r DITStructureRules) OID() string { return `2.5.21.1` }

/*
Contains returns the integer index of a matching instance within the
receiver instance. The match is conducted using the input id value
against the numeric OID or NAME clauses.

Neither whitespace nor case folding are significant in the matching
process.
*/
func (r DITStructureRules) Contains(id string) (idx int) {
	idx = -1
	id = trim(id, ` `)
	for i := 0; i < r.Len(); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].RuleID == id

		if fn || fi {
			idx = i
			break
		}
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITStructureRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
DITStructureRuleDescription implements [§ 4.1.7.1 of RFC 4512].

[§ 4.1.7.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1
*/
type DITStructureRuleDescription struct {
	RuleID      string
	Name        []string
	Description string
	Obsolete    bool
	Form        string
	SuperRules  []string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITStructureRuleDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.RuleID + ` `
		if len(r.Name) > 0 {
			def += stringQuotedDescrs(r.Name)
		}

		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}

		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += ` FORM ` + r.Form

		if len(r.SuperRules) > 0 {
			def += ` SUP ` + stringDescrs(r.SuperRules, ` `)
		}

		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITStructureRuleDescription) Valid() bool {
	return len(r.RuleID) > 0 && len(r.Form) > 0
}

func lDAPSyntaxDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "LDAPSyntaxDescription"); err == nil {
		_, err = marshalLDAPSyntaxDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalLDAPSyntaxDescription(input string) (def LDAPSyntaxDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == `(` {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "DESC":
			def.Description = parseSingleVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: '" + token + "'")
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func matchingRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "MatchingRuleDescription"); err == nil {
		_, err := marshalMatchingRuleDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalMatchingRuleDescription(input string) (def MatchingRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "OBSOLETE":
			def.Obsolete = true
		case "SYNTAX":
			def.Syntax = tkz.nextToken()
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func matchingRuleUseDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "MatchingRuleUseDescription"); err == nil {
		_, err := marshalMatchingRuleUseDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalMatchingRuleUseDescription(input string) (def MatchingRuleUseDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "OBSOLETE":
			def.Obsolete = true
		case "APPLIES":
			def.Applies = parseMultiVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func attributeTypeDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "AttributeTypeDescription"); err == nil {
		_, err = marshalAttributeTypeDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalAttributeTypeDescription(input string) (def AttributeTypeDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "SUP":
			def.SuperType = tkz.nextToken()
		case "SUBSTR", "SUBSTRING", "EQUALITY", "ORDERING", "SYNTAX":
			err = def.handleSyntaxMatchingRules(token, tkz)
		case "SINGLE-VALUE", "COLLECTIVE", "OBSOLETE", "NO-USER-MODIFICATION":
			err = def.handleBoolean(token)
		case "USAGE":
			def.Usage = tkz.nextToken()
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func (r *AttributeTypeDescription) handleBoolean(token string) (err error) {
	switch token {
	case "OBSOLETE":
		r.Obsolete = true
	case "NO-USER-MODIFICATION":
		r.NoUserModification = true
	case "SINGLE-VALUE":
		if r.Collective {
			err = errorTxt("Attribute cannot be both COLLECTIVE and SINGLE-VALUE")
			break
		}
		r.Single = true
	case "COLLECTIVE":
		if r.Single {
			err = errorTxt("Attribute cannot be both COLLECTIVE and SINGLE-VALUE")
			break
		}
		r.Collective = true
	}

	return
}

func (r *AttributeTypeDescription) handleSyntaxMatchingRules(token string, tkz *schemaTokenizer) (err error) {
	switch token {
	case "EQUALITY":
		r.Equality = tkz.nextToken()
	case "ORDERING":
		r.Ordering = tkz.nextToken()
	case "SUBSTR", "SUBSTRING":
		r.Substring = tkz.nextToken()
	case "SYNTAX":
		r.MinUpperBounds, r.Syntax, err = trimAttributeSyntaxMUB(tkz.nextToken())
	}

	return
}

func trimAttributeSyntaxMUB(x string) (mub uint, syntax string, err error) {
	syntax = x
	if idx := stridx(x, `{`); idx != -1 {
		syntax = x[:idx]
		raw := trim(x[idx+1:], `}`)
		var _mub int
		if _mub, err = atoi(raw); err == nil && raw[0] != '-' {
			mub = uint(_mub)
		}
	}

	return
}

func objectClassDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "ObjectClassDescription"); err == nil {
		_, err = marshalObjectClassDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalObjectClassDescription(input string) (def ObjectClassDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "STRUCTURAL", "AUXILIARY", "ABSTRACT":
			def.Kind = parseClassKind(token)
		case "OBSOLETE":
			def.Obsolete = true
		case "SUP":
			def.SuperClasses = parseMultiVal(tkz)
		case "MUST":
			def.Must = parseMultiVal(tkz)
		case "MAY":
			def.May = parseMultiVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func parseClassKind(token string) (kind uint8) {
	k, err := puint(token, 10, 8)
	if err == nil {
		kind = uint8(k)
	}
	return
}

func dITContentRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "DITContentRuleDescription"); err == nil {
		_, err = marshalDITContentRuleDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalDITContentRuleDescription(input string) (def DITContentRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next() // Move past the opening parenthesis
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "OBSOLETE":
			def.Obsolete = true
		case "AUX":
			def.Aux = parseMultiVal(tkz)
		case "MUST":
			def.Must = parseMultiVal(tkz)
		case "MAY":
			def.May = parseMultiVal(tkz)
		case "NOT":
			def.Not = parseMultiVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func nameFormDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "NameFormDescription"); err == nil {
		_, err = marshalNameFormDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalNameFormDescription(input string) (def NameFormDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "OBSOLETE":
			def.Obsolete = true
		case "OC":
			def.OC = parseSingleVal(tkz)
		case "MUST":
			def.Must = parseMultiVal(tkz)
		case "MAY":
			def.May = parseMultiVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func dITStructureRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "DITStructureRuleDescription"); err == nil {
		_, err = marshalDITStructureRuleDescription(str)
		result.Set(err == nil)
	}
	return
}

func marshalDITStructureRuleDescription(input string) (def DITStructureRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.RuleID = tkz.this()

	for tkz.next() {
		switch token := tkz.this(); token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "NAME":
			def.Name = parseMultiVal(tkz)
		case "DESC":
			def.Description = parseSingleVal(tkz)
		case "OBSOLETE":
			def.Obsolete = true
		case "FORM":
			def.Form = parseSingleVal(tkz)
		case "SUP":
			def.SuperRules = parseMultiVal(tkz)
		default:
			if hasPfx(token, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: token,
					Values:  parseMultiVal(tkz),
				}
			} else {
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func parseMultiVal(tkz *schemaTokenizer) (values []string) {
	token := tkz.nextToken()
	if token == "(" {
		for tkz.next() {
			token := tkz.this()
			if token == ")" {
				break
			} else if token == "$" {
				continue
			}
			values = append(values, trim(token, "'"))
		}
	} else {
		values = append(values, trim(token, "'"))
	}
	return
}

func parseSingleVal(tkz *schemaTokenizer) (val string) {
	return trim(tkz.nextToken(), `'`)
}

type schemaTokenizer struct {
	input []rune
	pos   int
	cur   string
}

func newSchemaTokenizer(input string) *schemaTokenizer {
	return &schemaTokenizer{input: []rune(input), pos: 0}
}

func (t *schemaTokenizer) next() bool {
	t.skipWhitespace()
	if t.pos >= len(t.input) {
		return false
	}

	start := t.pos
	if t.input[t.pos] == '\'' {
		t.pos++
		for t.pos < len(t.input) && (t.input[t.pos] != '\'' || (t.pos > start && t.input[t.pos-1] == '\\')) {
			t.pos++
		}
		t.pos++
	} else if t.input[t.pos] == '(' || t.input[t.pos] == ')' {
		t.pos++
	} else {
		for t.pos < len(t.input) && !isSpace(t.input[t.pos]) && t.input[t.pos] != '(' && t.input[t.pos] != ')' {
			t.pos++
		}
	}
	t.cur = string(t.input[start:t.pos])
	return true
}

func (t *schemaTokenizer) this() string {
	return t.cur
}

func (t *schemaTokenizer) isFinalToken() bool {
	t.skipWhitespace()
	return t.pos >= len(t.input)
}

func (t *schemaTokenizer) nextToken() string {
	t.next()
	return t.cur
}

func (t *schemaTokenizer) skipWhitespace() {
	for t.pos < len(t.input) && isSpace(t.input[t.pos]) {
		t.pos++
	}
}

func stringDescrs(x []string, delim string) (descrs string) {
	if len(x) == 1 {
		descrs = x[0]
	} else if len(x) > 1 {
		descrs = `( ` + join(x, delim) + ` )`
	}

	return
}

func stringQuotedDescrs(x []string) (descrs string) {
	if len(x) == 1 {
		descrs = `'` + x[0] + `'`
	} else if len(x) > 1 {
		descrs = `(`
		for i := 0; i < len(x); i++ {
			descrs += ` '` + x[i] + `'`
		}
		descrs += ` )`
	}

	return
}

func stringExtensions(exts map[int]Extension) (s string) {
	var ct int = len(exts)
	for i := 0; i < ct; i++ {
		if _, found := exts[i]; found {
			s += exts[i].String()
		} else {
			ct++
		}
	}

	return
}

func stringBooleanClause(token string, b bool) (clause string) {
	if b {
		clause = token
	}

	return
}

func trimDefinitionLabelToken(input string) string {
	low := lc(input)
	for _, token := range headerTokens {
		if hasPfx(low, lc(token)) {
			rest := input[len(token):]

			// Skip optional colon or space
			rest = trimL(rest, ": ")

			// Ensure we stop at the opening parenthesis
			if idx := stridx(rest, "("); idx != -1 {
				return rest
			}

			return rest
		}
	}

	return input
}

func (r LDAPSyntaxDescription) OID() string       { return `1.3.6.1.4.1.1466.115.121.1.54` }
func (r MatchingRuleDescription) OID() string     { return `1.3.6.1.4.1.1466.115.121.1.30` }
func (r AttributeTypeDescription) OID() string    { return `1.3.6.1.4.1.1466.115.121.1.3` }
func (r MatchingRuleUseDescription) OID() string  { return `1.3.6.1.4.1.1466.115.121.1.31` }
func (r ObjectClassDescription) OID() string      { return `1.3.6.1.4.1.1466.115.121.1.37` }
func (r DITContentRuleDescription) OID() string   { return `1.3.6.1.4.1.1466.115.121.1.16` }
func (r NameFormDescription) OID() string         { return `1.3.6.1.4.1.1466.115.121.1.35` }
func (r DITStructureRuleDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.17` }

func (r LDAPSyntaxes) Len() int      { return len(r) }
func (r MatchingRules) Len() int     { return len(r) }
func (r AttributeTypes) Len() int    { return len(r) }
func (r MatchingRuleUse) Len() int   { return len(r) }
func (r ObjectClasses) Len() int     { return len(r) }
func (r DITContentRules) Len() int   { return len(r) }
func (r NameForms) Len() int         { return len(r) }
func (r DITStructureRules) Len() int { return len(r) }

func (r LDAPSyntaxes) Type() string      { return `ldapSyntaxes` }
func (r MatchingRules) Type() string     { return `matchingRules` }
func (r AttributeTypes) Type() string    { return `attributeTypes` }
func (r MatchingRuleUse) Type() string   { return `matchingRuleUse` }
func (r ObjectClasses) Type() string     { return `objectClasses` }
func (r DITContentRules) Type() string   { return `dITContentRules` }
func (r NameForms) Type() string         { return `nameForms` }
func (r DITStructureRules) Type() string { return `dITStructureRules` }

func (r LDAPSyntaxDescription) Type() string       { return `ldapSyntax` }
func (r MatchingRuleDescription) Type() string     { return `matchingRule` }
func (r AttributeTypeDescription) Type() string    { return `attributeType` }
func (r MatchingRuleUseDescription) Type() string  { return `matchingRuleUse` }
func (r ObjectClassDescription) Type() string      { return `objectClass` }
func (r DITContentRuleDescription) Type() string   { return `dITContentRule` }
func (r NameFormDescription) Type() string         { return `nameForm` }
func (r DITStructureRuleDescription) Type() string { return `dITStructureRule` }

func (r LDAPSyntaxDescription) isDefinition()       {}
func (r MatchingRuleDescription) isDefinition()     {}
func (r AttributeTypeDescription) isDefinition()    {}
func (r MatchingRuleUseDescription) isDefinition()  {}
func (r ObjectClassDescription) isDefinition()      {}
func (r DITContentRuleDescription) isDefinition()   {}
func (r NameFormDescription) isDefinition()         {}
func (r DITStructureRuleDescription) isDefinition() {}

func (r LDAPSyntaxes) isDefinitions()      {}
func (r MatchingRules) isDefinitions()     {}
func (r AttributeTypes) isDefinitions()    {}
func (r MatchingRuleUse) isDefinitions()   {}
func (r ObjectClasses) isDefinitions()     {}
func (r DITContentRules) isDefinitions()   {}
func (r NameForms) isDefinitions()         {}
func (r DITStructureRules) isDefinitions() {}

var headerTokens []string = []string{
	"ldapSyntaxes", "ldapSyntax",
	"matchingRules", "matchingRule",
	"attributeTypes", "attributeType",
	"objectClasses", "objectClass",
	"dITContentRules", "dITContentRule",
	"nameForms", "nameForm",
	"dITStructureRules", "dITStructureRule",
}

var primerSyntaxes []string = []string{
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.1
	    DESC 'ACI Item'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.2
	    DESC 'Access Point'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.3
	    DESC 'Attribute Type Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.4
	    DESC 'Audio'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.5
	    DESC 'Binary'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.6
	    DESC 'Bit String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.7
	    DESC 'Boolean'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.11
	    DESC 'Country String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.12
	    DESC 'DN'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.13
	    DESC 'Data Quality Syntax'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.14
	    DESC 'Delivery Method'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.15
	    DESC 'Directory String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.16
	    DESC 'DIT Content Rule Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.17
	    DESC 'DIT Structure Rule Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.18
	    DESC 'DL Submit Permission'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.19
	    DESC 'DSA Quality Syntax'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.20
	    DESC 'DSE Type'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.21
	    DESC 'Enhanced Guide'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.22
	    DESC 'Facsimile Telephone Number'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.23
	    DESC 'Fax'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.24
	    DESC 'Generalized Time'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.25
	    DESC 'Guide'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.26
	    DESC 'IA5 String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.27
	    DESC 'INTEGER'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.28
	    DESC 'JPEG'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.30
	    DESC 'Matching Rule Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.31
	    DESC 'Matching Rule Use Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.32
	    DESC 'Mail Preference'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.33
	    DESC 'MHS OR Address'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.34
	    DESC 'Name And Optional UID'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.35
	    DESC 'Name Form Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.36
	    DESC 'Numeric String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.37
	    DESC 'Object Class Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.38
	    DESC 'OID'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.39
	    DESC 'Other Mailbox'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.40
	    DESC 'Octet String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.41
	    DESC 'Postal Address'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.42
	    DESC 'Protocol Information'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.43
	    DESC 'Presentation Address'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.44
	    DESC 'Printable String'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.45
	    DESC 'Subtree Specification'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.46
	    DESC 'Supplier Information'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.47
	    DESC 'Supplier Or Consumer'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.48
	    DESC 'Supplier And Consumer'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.50
	    DESC 'Telephone Number'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.51
	    DESC 'Teletex Terminal Identifier'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.52
	    DESC 'Telex Number'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.53
	    DESC 'UTC Time'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.54
	    DESC 'LDAP Syntax Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.55
	    DESC 'Modify Rights'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.56
	    DESC 'LDAP Schema Definition'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.57
	    DESC 'LDAP Schema Description'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.58
	    DESC 'Substring Assertion'
	    X-ORIGIN 'RFC4517' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.8
	    DESC 'Certificate'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.9
	    DESC 'Certificate List'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.10
	    DESC 'Certificate Pair'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.4.1.1466.115.121.1.49
	    DESC 'Supported Algorithm'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.1
	    DESC 'X.509 Certificate Exact Assertion'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.2
	    DESC 'X.509 Certificate Assertion'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.3
	    DESC 'X.509 Certificate Pair Exact Assertion'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.4
	    DESC 'X.509 Certificate Pair Assertion'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.5
	    DESC 'X.509 Certificate List Exact Assertion'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.6
	    DESC 'X.509 Certificate List Assertion'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.15.7
	    DESC 'X.509 Algorithm Identifier'
	    X-NOT-HUMAN-READABLE 'TRUE'
	    X-ORIGIN 'RFC4523' )`,
	`ldapSyntax: ( 1.3.6.1.1.16.1
	    DESC 'UUID'
	    X-ORIGIN 'RFC4530' )`,
	`ldapSyntax: ( 1.3.6.1.1.1.0.0
	    DESC 'nisNetgroupTripleSyntax'
	    X-ORIGIN 'RFC2307' )`,
	`ldapSyntax: ( 1.3.6.1.1.1.0.1
	    DESC 'bootParameterSyntax'
	    X-ORIGIN 'RFC2307' )`,
}

var primerMatchingRules []string = []string{
	`matchingRule: ( 1.3.6.1.4.1.4203.1.2.1
	    NAME 'caseExactIA5SubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
	    X-ORIGIN 'RFC2307' )`,
	`matchingRule: ( 2.5.13.0
	    NAME 'objectIdentifierMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.1
	    NAME 'distinguishedNameMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.2
	    NAME 'caseIgnoreMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.3
	    NAME 'caseIgnoreOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.4
	    NAME 'caseIgnoreSubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.5
	    NAME 'caseExactMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.6
	    NAME 'caseExactOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.7
	    NAME 'caseExactSubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.8
	    NAME 'numericStringMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.36
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.9
	    NAME 'numericStringOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.36
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.10
	    NAME 'numericStringSubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 1.3.6.1.4.1.1466.109.114.2
	    NAME 'caseIgnoreIA5Match'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 1.3.6.1.4.1.1466.109.114.1
	    NAME 'caseExactIA5Match'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 1.3.6.1.4.1.1466.109.114.3
	    NAME 'caseIgnoreIA5SubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.11
	    NAME 'caseIgnoreListMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.41
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.12
	    NAME 'caseIgnoreListSubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.13
	    NAME 'booleanMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.14
	    NAME 'integerMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.15
	    NAME 'integerOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.16
	    NAME 'bitStringMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.6
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.17
	    NAME 'octetStringMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.18
	    NAME 'octetStringOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.22
	    NAME 'presentationAddressMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.43
	    X-ORIGIN 'RFC2256' )`,
	`matchingRule: ( 2.5.13.24
	    NAME 'protocolInformationMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.42
	    X-ORIGIN 'RFC2252' )`,
	`matchingRule: ( 2.5.13.20
	    NAME 'telephoneNumberMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.50
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.21
	    NAME 'telephoneNumberSubstringsMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.58
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.23
	    NAME 'uniqueMemberMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.34
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.27
	    NAME 'generalizedTimeMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.28
	    NAME 'generalizedTimeOrderingMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.29
	    NAME 'integerFirstComponentMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.30
	    NAME 'objectIdentifierFirstComponentMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.31
	    NAME 'directoryStringFirstComponentMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.32
	    NAME 'wordMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.33
	    NAME 'keywordMatch'
	    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	    X-ORIGIN 'RFC4517' )`,
	`matchingRule: ( 2.5.13.34
	    NAME 'certificateExactMatch'
	    SYNTAX 1.3.6.1.1.15.1
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.35
	    NAME 'certificateMatch'
	    SYNTAX 1.3.6.1.1.15.2
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.36
	    NAME 'certificatePairExactMatch'
	    SYNTAX 1.3.6.1.1.15.3
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.37
	    NAME 'certificatePairMatch'
	    SYNTAX 1.3.6.1.1.15.4
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.38
	    NAME 'certificateListExactMatch'
	    SYNTAX 1.3.6.1.1.15.5
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.39
	    NAME 'certificateListMatch'
	    SYNTAX 1.3.6.1.1.15.6
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 2.5.13.40
	    NAME 'algorithmIdentifierMatch'
	    SYNTAX 1.3.6.1.1.15.7
	    X-ORIGIN 'RFC4523' )`,
	`matchingRule: ( 1.3.6.1.1.16.2
	    NAME 'uuidMatch'
	    SYNTAX 1.3.6.1.1.16.1
	    X-ORIGIN 'RFC4530' )`,
	`matchingRule: ( 1.3.6.1.1.16.3
	    NAME 'uuidOrderingMatch'
	    SYNTAX 1.3.6.1.1.16.1
	    X-ORIGIN 'RFC4530' )`,
}
