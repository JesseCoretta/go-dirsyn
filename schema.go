package dirsyn

/*
schema.go implements much of Section 4 of RFC 4512.
*/

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
		r.AddLDAPSyntax(tv)
		//case MatchingRuleDescription:
		//	r.LDAPSyntaxes = append(r.LDAPSyntaxes, tv)
		//case AttributeTypeDescription:
		//	r.LDAPSyntaxes = append(r.LDAPSyntaxes, tv)
		//case ObjectClassDescription:
		//	r.LDAPSyntaxes = append(r.LDAPSyntaxes, tv)
		//case DITContentRuleDescription:
		//	r.DITContentRules = append(r.DITContentRules, tv)
		//case NameFormDescription:
		//	r.NameForms = append(r.NameForms, tv)
		//case DITStructureRuleDescription:
		//	r.DITStructureRules = append(r.DITStructureRules, tv)
	}
}

/*
AddLDAPSyntax returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [LDAPSyntaxDescription], or its
equivalent string representation as described in [§ 4.1.5 of RFC 4512].

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
func (r *SubschemaSubentry) AddLDAPSyntax(input any) (err error) {
	var def LDAPSyntaxDescription
	switch tv := input.(type) {
	case LDAPSyntaxDescription:
		def = tv
	case string:
		def, err = parseLDAPSyntaxDescription(tv)
	}

	if def.Valid() {
		r.LDAPSyntaxes = append(r.LDAPSyntaxes, def)
	}

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
	for i := 0; i < len(r); i++ {
		s += `ldapSyntaxes: ` + r[i].String() + string(rune(10))
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
	for i := 0; i < len(r); i++ {
		desc := repAll(r[i].Description, ` `, ``)
		fn := eqf(id, desc)
		fi := r[i].OID == id

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
	OID         string
	Description string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntaxDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.OID + ` `
		if len(r.Description) > 0 {
			def += ` DESC '` + r.Description + `'`
		}
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Valid returns a Boolean value indicative of a valid receiver instance.
*/
func (r LDAPSyntaxDescription) Valid() bool {
	return len(r.OID) > 0
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
	for i := 0; i < len(r); i++ {
		s += `matchingRuleUse: ` + r[i].String() + string(rune(10))
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
	for i := 0; i < len(r); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].OID == id

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
	OID         string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0 &&
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
	for i := 0; i < len(r); i++ {
		s += `attributeTypes: ` + r[i].String() + string(rune(10))
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
	for i := 0; i < len(r); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].OID == id

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
	OID                string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0 &&
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
	for i := 0; i < len(r); i++ {
		s += `matchingRuleUses: ` + r[i].String() + string(rune(10))
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
	OID         string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0 &&
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
	for i := 0; i < len(r); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].OID == id

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
	for i := 0; i < len(r); i++ {
		s += `objectClasses: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
ObjectClassDescription implements [§ 4.1.1 of RFC 4512].

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
type ObjectClassDescription struct {
	OID          string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0
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
	for i := 0; i < len(r); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].OID == id

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
	for i := 0; i < len(r); i++ {
		s += `dITContentRules: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
DITContentRuleDescription implements [§ 4.1.6 of RFC 4512].

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
type DITContentRuleDescription struct {
	OID         string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0
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
	for i := 0; i < len(r); i++ {
		fn := strInSlice(id, r[i].Name)
		fi := r[i].OID == id

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
	for i := 0; i < len(r); i++ {
		s += `nameForms: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
NameFormDescription implements [§ 4.1.7.2 of RFC 4512].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
type NameFormDescription struct {
	OID         string
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
		def = `( ` + r.OID + ` `
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
	return len(r.OID) > 0 && len(r.OC) > 0 && len(r.Must) > 0
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
	for i := 0; i < len(r); i++ {
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
	for i := 0; i < len(r); i++ {
		s += `dITStructureRules: ` + r[i].String() + string(rune(10))
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

func parseLDAPSyntaxDescription(input string) (def LDAPSyntaxDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.OID = tkz.this()

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
				err = errorTxt("Unknown token in definition: " + token)
			}
		}

		if err != nil {
			break
		}
	}

	return
}

func parseMatchingRuleDescription(input string) (def MatchingRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.OID = tkz.this()

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

func parseAttributeTypeDescription(input string) (def AttributeTypeDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.OID = tkz.this()

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

func parseObjectClassDescription(input string) (def ObjectClassDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.OID = tkz.this()

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

func parseDITContentRuleDescription(input string) (def DITContentRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next() // Move past the opening parenthesis
	}

	def.OID = tkz.this()

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

func parseNameFormDescription(input string) (def NameFormDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
	tkz := newSchemaTokenizer(input)

	if tkz.next() && tkz.this() == "(" {
		tkz.next()
	}

	def.OID = tkz.this()

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

func parseDITStructureRuleDescription(input string) (def DITStructureRuleDescription, err error) {
	def.Extensions = make(map[int]Extension)

	input = trimS(input)
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

func parseSingleVal(tkz *schemaTokenizer) string {
	token := tkz.nextToken()
	return trim(token, "'")
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
