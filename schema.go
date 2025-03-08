package dirsyn

/*
schema.go implements much of Section 4 of RFC 4512.
*/

import "sync"

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
	IsZero() bool
	Identifier() string
	Type() string
	Valid() bool
	String() string
	XOrigin() []string
	isDefinition()
}

/*
Definitions is an interface type qualified through instances of the
following types:

  - [LDAPSyntaxDescriptions]
  - [MatchingRuleDescriptions]
  - [AttributeTypeDescriptions]
  - [MatchingRuleUseDescriptions]
  - [ObjectClassDescriptions]
  - [DITContentRuleDescriptions]
  - [NameFormDescriptions]
  - [DITStructureRuleDescriptions]
*/
type Definitions interface {
	Len() int
	OID() string
	Type() string
	IsZero() bool
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
	LDAPSyntaxDescriptions
	MatchingRuleDescriptions
	AttributeTypeDescriptions
	MatchingRuleUseDescriptions
	ObjectClassDescriptions
	DITContentRuleDescriptions
	NameFormDescriptions
	DITStructureRuleDescriptions

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
OID returns the numeric OID literal "2.5.18.10" per [§ 4.2 of RFC 4512].

[§ 4.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2
*/
func (r SubschemaSubentry) OID() string { return `2.5.18.10` }

/*
String returns the string representation of the receiver instance.
*/
func (r SubschemaSubentry) String() (ssse string) {

	ssse += r.LDAPSyntaxDescriptions.String()
	ssse += r.MatchingRuleDescriptions.String()
	ssse += r.AttributeTypeDescriptions.String()
	ssse += r.MatchingRuleUseDescriptions.String()
	ssse += r.ObjectClassDescriptions.String()
	ssse += r.DITContentRuleDescriptions.String()
	ssse += r.NameFormDescriptions.String()
	ssse += r.DITStructureRuleDescriptions.String()

	// remove final newline
	ssse = trim(ssse, string(rune(10)))

	return
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
		if !tv.Valid() {
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

	if _, idx := r.LDAPSyntax(def.NumericOID); idx != -1 {
		err = errorTxt("ldapSyntax: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.LDAPSyntaxDescriptions = append(r.LDAPSyntaxDescriptions, def)

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
		if _, idx := r.LDAPSyntax(def.Syntax); idx == -1 {
			err = errorTxt("matchingRule: Unknown SYNTAX '" + def.Syntax + "'")
			return
		}
	}

	if _, idx := r.MatchingRule(def.NumericOID); idx != -1 {
		err = errorTxt("matchingRule: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	if !def.Valid() {
		err = errorTxt("matchingRule: Invalid description syntax")
		return
	}

	// Initialize MRU using new MR def.
	mru := def.newMatchingRuleUse()

	r.lock.Lock()
	defer r.lock.Unlock()

	r.MatchingRuleDescriptions = append(r.MatchingRuleDescriptions, def)
	if mru.NumericOID != "" {
		r.MatchingRuleUseDescriptions = append(r.MatchingRuleUseDescriptions, mru)
	}

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
		def = tv
	case string:
		def, err = marshalAttributeTypeDescription(tv)
	default:
		err = errorBadType("AttributeTypeDescription")
	}

	if err != nil {
		return
	}

	if _, idx := r.AttributeType(def.NumericOID); idx != -1 {
		err = errorTxt("attributeType: Duplicate registration: '" +
			def.NumericOID + "'")
		return
	}

	// store whatever MRs we validate
	var mrups map[string]string = make(map[string]string, 3)

	for typ, mr := range map[string]string{
		"EQUALITY": def.Equality,
		"ORDERING": def.Ordering,
		"SUBSTR":   def.Substring,
	} {
		if mr != "" {
			var rule MatchingRuleDescription
			var idx int

			if rule, idx = r.MatchingRule(mr); idx == -1 {
				err = errorTxt("attributeType: Unknown " + typ +
					" matching rule: '" + mr + "'")
				return
			}

			mrups[typ] = rule.NumericOID
		}
	}

	// Make sure supertype, if present, is sane.
	if def.SuperType != "" {
		if _, idx := r.AttributeType(def.SuperType); idx == -1 {
			err = errorTxt("attributeType: Unknown SUP (supertype): '" +
				def.SuperType + "'")
			return
		}
	}

	if len(def.Syntax) > 0 {
		if _, idx := r.LDAPSyntax(def.Syntax); idx == -1 {
			err = errorTxt("attributeType: Unknown SYNTAX '" + def.Syntax + "'")
			return
		}
	}

	if !def.Valid() {
		err = errorTxt("attributeType: Invalid description syntax")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.AttributeTypeDescriptions = append(r.AttributeTypeDescriptions, def)
	r.updateMatchingRuleUse(def, mrups)

	return
}

func (r *SubschemaSubentry) updateMatchingRuleUse(def AttributeTypeDescription, mrups map[string]string) {
	name := def.NumericOID
	if len(def.Name) > 0 {
		// Use the principal NAME, if set.
		name = def.Name[0]
	}

	// Update appropriate MRUs to include new attr OID
	for _, v := range mrups {
		if _, idx := r.MatchingRuleUse(v); idx != -1 {
			if found := strInSlice(name, r.MatchingRuleUseDescriptions[idx].Applies); !found {
				r.MatchingRuleUseDescriptions[idx].Applies =
					append(r.MatchingRuleUseDescriptions[idx].Applies, name)
			}
		}
	}
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
		def = tv
	case string:
		def, err = marshalObjectClassDescription(tv)
	default:
		err = errorBadType("ObjectClassDescription")
	}

	if err != nil {
		return
	}

	if _, idx := r.ObjectClass(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeType(at); idx == -1 {
				err = errorTxt("objectClass: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	// Make sure superclasses, if present, are sane.
	for i := 0; i < len(def.SuperClasses); i++ {
		if _, idx := r.ObjectClass(def.SuperClasses[i]); idx == -1 {
			err = errorTxt("objectClass: Unknown SUP (superclass): '" +
				def.SuperClasses[i] + "'")
			return
		}
	}

	if !def.Valid() {
		err = errorTxt("objectClass: failed validity checks")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.ObjectClassDescriptions = append(r.ObjectClassDescriptions, def)

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
		def = tv
	case string:
		def, err = marshalDITContentRuleDescription(tv)
	default:
		err = errorBadType("DITContentRuleDescription")
	}

	if err != nil {
		return
	}

	if _, idx := r.ObjectClass(def.NumericOID); idx == -1 {
		err = errorTxt("dITContentRule: Unregistered structural class OID: '" +
			def.NumericOID + "'")
		return
	} else if _, idx := r.DITContentRule(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeType(at); idx == -1 {
				err = errorTxt("dITContentRule: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	// Make sure auxiliary classes, if present, are sane.
	for i := 0; i < len(def.Aux); i++ {
		if _, idx := r.ObjectClass(def.Aux[i]); idx == -1 {
			err = errorTxt("dITContentRule: Unknown AUX (auxiliary class): '" +
				def.Aux[i] + "'")
			return
		} else if r.ObjectClassDescriptions[idx].Kind != 1 {
			err = errorTxt("dITContentRule: non-AUXILIARY class in AUX clause: '" +
				def.Aux[i] + "'")
			return
		}
	}

	if !def.Valid() {
		err = errorTxt("dITContentRule: Invalid description syntax")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.DITContentRuleDescriptions = append(r.DITContentRuleDescriptions, def)

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
		def = tv
	case string:
		def, err = marshalNameFormDescription(tv)
	default:
		err = errorBadType("NameFormDescription")
	}

	if err != nil {
		return
	}

	oc, idx := r.ObjectClass(def.OC)
	if idx == -1 || oc.Kind != 0 {
		err = errorTxt("nameForm: Unknown or invalid structural class OID: '" +
			def.OC + "'")
		return
	}

	if _, idx = r.NameForm(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeType(at); idx == -1 {
				err = errorTxt("nameForm: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	if !def.Valid() {
		err = errorTxt("nameForm: Invalid description syntax")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.NameFormDescriptions = append(r.NameFormDescriptions, def)

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
		def = tv
	case string:
		def, err = marshalDITStructureRuleDescription(tv)
	default:
		err = errorBadType("DITStructureRuleDescription")
	}

	if err != nil {
		return
	}

	if _, idx := r.DITStructureRule(def.RuleID); idx != -1 {
		err = errorTxt("dITStructureRule: Duplicate registration: '" +
			def.RuleID + "'")
		return
	} else if _, idx := r.NameForm(def.Form); idx == -1 {
		err = errorTxt("dITStructureRule: nameForm: Unknown name form OID: '" +
			def.Form + "'")
		return
	}

	// Make sure superior structure rules, if present, are sane.
	for i := 0; i < len(def.SuperRules); i++ {
		if _, idx := r.DITStructureRule(def.SuperRules[i]); idx == -1 {
			// Allow recursive rules to be added (ignore
			// "Not Found" for current ruleid).
			if def.SuperRules[i] != def.RuleID {
				err = errorTxt("dITStructureRule: Unknown SUP (superior rule): '" +
					def.SuperRules[i] + "'")
				return
			}
		}
	}

	if !def.Valid() {
		err = errorTxt("dITStructureRule: Invalid description syntax")
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.DITStructureRuleDescriptions = append(r.DITStructureRuleDescriptions, def)

	return
}

/*
Counters returns an instance of [9]uint, each slice representing the
current number of [Definition] instances of a particular collection,
while the final slice represents the sum total of the previous eight (8).

Collection indices are as follows:

  - 0 - "LDAPSyntaxDescriptions"
  - 1 - "MatchingRuleDescriptions"
  - 2 - "AttributeTypeDescriptions"
  - 3 - "MatchingRuleUseDescriptions"
  - 4 - "ObjectClassDescriptions"
  - 5 - "DITContentRuleDescriptions"
  - 6 - "NameFormDescriptions"
  - 7 - "DITStructureRuleDescriptions"
  - 8 - "total"

As the return type is fixed, there is no risk of panic when calling
indices 0 through 8 in any circumstance.
*/
func (r SubschemaSubentry) Counters() (counters [9]uint) {
	counters[0] = uint(r.LDAPSyntaxDescriptions.Len())
	counters[1] = uint(r.MatchingRuleDescriptions.Len())
	counters[2] = uint(r.AttributeTypeDescriptions.Len())
	counters[3] = uint(r.MatchingRuleUseDescriptions.Len())
	counters[4] = uint(r.ObjectClassDescriptions.Len())
	counters[5] = uint(r.DITContentRuleDescriptions.Len())
	counters[6] = uint(r.NameFormDescriptions.Len())
	counters[7] = uint(r.DITStructureRuleDescriptions.Len())

	// Perform summation of all of the above.
	counters[8] = uint(counters[0] +
		counters[1] +
		counters[2] +
		counters[3] +
		counters[4] +
		counters[5] +
		counters[6] +
		counters[7])

	return
}

/*
LDAPSyntax returns an instance of [LDAPSyntaxDescription] alongside the
associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired LDAPSyntax numeric OID, or the description text.

Note that if description text is used, neither whitespace nor case-folding
are significant in the matching process.
*/
func (r SubschemaSubentry) LDAPSyntax(id string) (ls LDAPSyntaxDescription, idx int) {
	idx = -1
	desc := trimS(repAll(id, ` `, ``))
	for i := 0; i < r.LDAPSyntaxDescriptions.Len(); i++ {
		def := r.LDAPSyntaxDescriptions[i]
		ldesc := repAll(def.Description, ` `, ``)
		fo := def.NumericOID == id
		fn := streqf(ldesc, desc)
		if fo || fn {
			ls = def
			idx = i
			break
		}
	}

	return
}

/*
MatchingRule returns an instance of [MatchingRuleDescription] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired MatchingRule numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) MatchingRule(id string) (mr MatchingRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.MatchingRuleDescriptions.Len(); i++ {
		def := r.MatchingRuleDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			mr = def
			idx = i
			break
		}
	}

	return
}

/*
MatchingRuleUse returns an instance of [MatchingRuleUseDescription] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired MatchingRuleUse numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) MatchingRuleUse(id string) (mr MatchingRuleUseDescription, idx int) {
	idx = -1
	for i := 0; i < r.MatchingRuleUseDescriptions.Len(); i++ {
		def := r.MatchingRuleUseDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			mr = def
			idx = i
			break
		}
	}

	return
}

/*
AttributeType returns an instance of [AttributeTypeDescription] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired AttributeType numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) AttributeType(id string) (at AttributeTypeDescription, idx int) {
	idx = -1
	for i := 0; i < r.AttributeTypeDescriptions.Len(); i++ {
		def := r.AttributeTypeDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			at = def
			idx = i
			break
		}
	}

	return
}

/*
ObjectClassID returns an instance of [ObjectClassDescription] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired ObjectClass numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) ObjectClass(id string) (oc ObjectClassDescription, idx int) {
	idx = -1
	for i := 0; i < r.ObjectClassDescriptions.Len(); i++ {
		def := r.ObjectClassDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			oc = def
			idx = i
			break
		}
	}

	return
}

/*
NameForm returns an instance of [NameFormDescription] alongside the
associated integer index. If not found, the index shall be -1 and
the schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of
the desired NameForm numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) NameForm(id string) (nf NameFormDescription, idx int) {
	idx = -1
	for i := 0; i < r.NameFormDescriptions.Len(); i++ {
		def := r.NameFormDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			nf = def
			idx = i
			break
		}
	}

	return
}

/*
DITContentRule returns an instance of [DITContentRuleDescription] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired DITContentRule numeric OID, or name.

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r SubschemaSubentry) DITContentRule(id string) (dc DITContentRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.DITContentRuleDescriptions.Len(); i++ {
		def := r.DITContentRuleDescriptions[i]
		fo := def.NumericOID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			dc = def
			idx = i
			break
		}
	}

	return
}

/*
DITStructureRule returns an instance of [DITStructureRuleDescription]
alongside the associated integer index. If not found, the index shall
be -1 and the schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of
the desired DITStructureRule integer identifier (rule ID), or name.

Note that if a name is used, case-folding is not significant in the
matching process.
*/
func (r SubschemaSubentry) DITStructureRule(id string) (ds DITStructureRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.DITStructureRuleDescriptions.Len(); i++ {
		def := r.DITStructureRuleDescriptions[i]
		fo := def.RuleID == id
		fn := strInSlice(id, def.Name)
		if fo || fn {
			ds = def
			idx = i
			break
		}
	}

	return
}

/*
SubRules returns slices of [DITStructureRuleDescription], each of
which are direct subordinate structure rules of the input string id.

The input string id must be the rule ID or name of the supposed superior
structure rule.

Note that if a name is used, case-folding is not significant in the matching
process.

If zero slices are returned, this can mean either the superior structure rule
was not found, or that it has no subordinate rules of its own.
*/
func (r SubschemaSubentry) SubRules(id string) (sub []DITStructureRuleDescription) {
	if rule, idx := r.DITStructureRule(id); idx != -1 {
		for i := 0; i < r.DITStructureRuleDescriptions.Len(); i++ {
			// NOTE - don't skip the superior rule itself,
			// as it may be a recursive (self-referencing)
			// structure rule.
			dsr := r.DITStructureRuleDescriptions[i]
			if strInSlice(rule.RuleID, dsr.SuperRules) {
				sub = append(sub, dsr)
			}
		}
	}

	return
}

/*
SuperiorStructureRules returns slices of [DITStructureRuleDescription], each of
which are direct superior structure rules of the input string id.

The input string id must be the rule ID or name of the subordinate structure rule.

Note that if a name is used, case-folding is not significant in the matching
process.

If zero slices are returned, this can mean either the structure rule was not
found, or that it has no superior rules of its own.
*/
func (r SubschemaSubentry) SuperiorStructureRules(id string) (sup []DITStructureRuleDescription) {
	if rule, idx := r.DITStructureRule(id); idx != -1 {
		for i := 0; i < len(rule.SuperRules); i++ {
			s := rule.SuperRules[i]

			// NOTE - don't skip the superior rule itself,
			// as it may be a recursive (self-referencing)
			// structure rule.
			if dsr, sidx := r.DITStructureRule(s); sidx != -1 {
				sup = append(sup, dsr)
			}
		}
	}

	return
}

/*
NamedObjectClass returns an instance of [ObjectClassDescription] alongside its
associated slice index within the receiver's object class collection.

The input id must be the integer identifier (rule ID) or name of a registered
[DITStructureRuleDescription] instance.

The return instance of [ObjectClassDescription] is resolved from the "OC" clause
found within the [NameFormDescription] beared by the [DITStructureRuleDescription].

The [ObjectClassDescription], if found, is guaranteed to be of the STRUCTURAL kind.
*/
func (r SubschemaSubentry) NamedObjectClass(id string) (noc ObjectClassDescription, idx int) {
	idx = -1
	if rule, sidx := r.DITStructureRule(id); sidx != -1 {
		if form, fidx := r.NameForm(rule.Form); fidx != -1 {
			if oc, oidx := r.ObjectClass(form.OC); oidx != -1 && oc.Kind == 0 {
				noc = oc
				idx = oidx
			}
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LDAPSyntaxDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeTypeDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleUseDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectClassDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITContentRuleDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NameFormDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITStructureRuleDescription) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LDAPSyntaxDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeTypeDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleUseDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectClassDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITContentRuleDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NameFormDescriptions) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITStructureRuleDescriptions) IsZero() bool { return r.Len() == 0 }

/*
SuperClassOf returns a Boolean value indicative of r being a superior ("SUP")
[ObjectClassDescription] of sub, which may be a string or bonafide instance of
[ObjectClassDescription].

Note: this will trace all super class chains indefinitely and, thus, will
recognize any superior association without regard for "depth".
*/
func (r ObjectClassDescription) SuperClassOf(sub any, classes ObjectClassDescriptions) (sup bool) {
	var subordinate ObjectClassDescription
	switch tv := sub.(type) {
	case string:
		// resolve to ObjectClassDescription
		var idx int
		if subordinate, idx = classes.Get(tv); idx == -1 {
			return
		}
	case ObjectClassDescription:
		subordinate = tv
	default:
		return
	}

	dsups := subordinate.SuperClasses
	for i := 0; i < len(dsups) && !sup; i++ {
		res, ridx := classes.Get(dsups[i])
		if ridx == -1 {
			break
		}

		if sup = res.NumericOID == r.NumericOID; sup {
			// direct (immediate) match by numeric OID
			break
		} else if sup = r.SuperClassOf(res, classes); sup {
			// match by traversal
			break
		}
	}

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
LDAPSyntaxDescriptions implements [§ 4.2.5 of RFC 4512] and contains slices of
[LDAPSyntaxDescription].

[§ 4.2.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.5
*/
type LDAPSyntaxDescriptions []LDAPSyntaxDescription

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntaxDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [LDAPSyntaxDescription] and a slice index following
a description or numeric OID match attempt. A zero instance of [LDAPSyntaxDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r LDAPSyntaxDescriptions) Get(term string) (def LDAPSyntaxDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
	}

	return
}

/*
LDAPSyntaxByIndex returns the Nth [LDAPSyntaxDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) LDAPSyntaxByIndex(idx int) (def LDAPSyntaxDescription) {
	if 0 <= idx && idx < r.LDAPSyntaxDescriptions.Len() {
		def = r.LDAPSyntaxDescriptions[idx]
	}

	return
}

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.101.120.16" per
[§ 4.2.5 of RFC 4512].

[§ 4.2.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.5
*/
func (r LDAPSyntaxDescriptions) OID() string { return `1.3.6.1.4.1.1466.101.120.16` }

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
		def = `( ` + r.NumericOID
		def += definitionDescription(r.Description)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the numeric OID by which the receiver is known.
*/
func (r LDAPSyntaxDescription) Identifier() string {
	return r.NumericOID
}

/*
xPattern returns the regular expression statement assigned to the receiver.
This will be used by [LDAPSyntaxDescription.Verify] method to validate a
value against a custom syntax.
*/
func (r LDAPSyntaxDescription) xPattern() (xpat string) {
	for _, ext := range r.Extensions {
		if ext.XString == `X-PATTERN` && len(ext.Values) == 1 {
			xpat = ext.Values[0]
			break
		}
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r LDAPSyntaxDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Description value.

Case is not significant in the matching process, and whitespace is disregarded
where a Description value is concerned.
*/
func (r LDAPSyntaxDescription) Match(term string) bool {
	return term == r.NumericOID || streqf(removeWHSP(term), removeWHSP(r.Description))
}

/*
HumanReadable returns a Boolean value indicative of whether the receiver
instance represents a human readable syntax.

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-NOT-HUMAN-READABLE` XString and a BOOLEAN ASN.1
value of `TRUE`.
*/
func (r LDAPSyntaxDescription) HumanReadable() (hr bool) {
	// Assume true by default, as most syntaxes
	// are, in fact, human readable.
	hr = true

	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-NOT-HUMAN-READABLE`) {
			if strInSlice(`TRUE`, ext.Values) &&
				len(ext.Values) == 1 {
				hr = false
				break
			}
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
	_, err := marshalNumericOID(r.NumericOID)
	return err == nil
}

/*
MatchingRuleDescriptions implements [§ 4.2.3 of RFC 4512] and contains slices of
[MatchingRuleDescription].

[§ 4.2.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.3
*/
type MatchingRuleDescriptions []MatchingRuleDescription

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [MatchingRuleDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [MatchingRuleDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRuleDescriptions) Get(term string) (def MatchingRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
	}

	return
}

/*
MatchingRuleIndex returns the Nth [MatchingRuleDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) MatchingRuleByIndex(idx int) (def MatchingRuleDescription) {
	if 0 <= idx && idx < r.MatchingRuleDescriptions.Len() {
		def = r.MatchingRuleDescriptions[idx]
	}

	return
}

/*
MatchingRuleUseIndex returns the Nth [MatchingRuleUseDescription] instances
found within the receiver instance.
*/
func (r SubschemaSubentry) MatchingRuleUseByIndex(idx int) (def MatchingRuleUseDescription) {
	if 0 <= idx && idx < r.MatchingRuleUseDescriptions.Len() {
		def = r.MatchingRuleUseDescriptions[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.4" per [§ 4.2.3 of RFC 4512].

[§ 4.2.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.3
*/
func (r MatchingRuleDescriptions) OID() string { return `2.5.21.4` }

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
EqualityMatch performs an equality match between the actual and assertion input
values. The actual value represents the value that would ostensibly be derived
from an LDAP DIT entry, while the assertion value represents the test value that
would be input by a requesting user.
*/
func (r MatchingRuleDescription) EqualityMatch(actual, assertion any) (result Boolean) {
	if funk, found := matchingRuleAssertions[r.NumericOID]; found {
		result, _ = funk(actual, assertion)
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition
originates.

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r MatchingRuleDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r MatchingRuleDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += ` SYNTAX ` + r.Syntax
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r MatchingRuleDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
newMatchingRuleUse initializes and returns a new instance of [MatchingRuleUseDescription].
*/
func (r MatchingRuleDescription) newMatchingRuleUse() (mru MatchingRuleUseDescription) {
	if r.Valid() {
		mru.NumericOID = r.NumericOID
		mru.Description = r.Description
		mru.Extensions = r.Extensions
	}

	return
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver instance.
Note this does not verify the presence of dependency schema elements.
*/
func (r MatchingRuleDescription) Valid() bool {
	_, oerr := marshalNumericOID(r.NumericOID)
	_, serr := marshalNumericOID(r.Syntax)
	return oerr == nil && serr == nil
}

/*
AttributeTypeDescriptions implements [§ 4.2.2 of RFC 4512] and contains slices of
[AttributeTypeDescription].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
*/
type AttributeTypeDescriptions []AttributeTypeDescription

/*
OID returns the numeric OID literal "2.5.21.5" per [§ 4.2.2 of RFC 4512].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
*/
func (r AttributeTypeDescriptions) OID() string { return `2.5.21.5` }

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypeDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [AttributeTypeDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [AttributeTypeDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r AttributeTypeDescriptions) Get(term string) (def AttributeTypeDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
	}

	return
}

/*
AttributeTypeIndex returns the Nth [AttributeTypeDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) AttributeTypeByIndex(idx int) (def AttributeTypeDescription) {
	if 0 <= idx && idx < r.AttributeTypeDescriptions.Len() {
		def = r.AttributeTypeDescriptions[idx]
	}

	return
}

/*
AttributeTypeDescription implements [§ 4.1.2 of RFC 4512] and [§ 13.4.8 of ITU-T Rec. X.501] (AttributeType).

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
[§ 13.4.8 of ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.520
*/
type AttributeTypeDescription struct {
	NumericOID         string            // "id"
	Name               []string          // "ldapName"
	Description        string            // "ldapDesc"
	SuperType          string            // "derivation"
	Obsolete           bool              // "obsolete"
	Single             bool              // "single-valued"
	Collective         bool              // "collective"
	NoUserModification bool              // "no-user-modification"
	MinUpperBounds     uint              // --
	Syntax             string            // "ldapSyntax"
	Equality           string            // "equality-match"
	Ordering           string            // "ordering-match"
	Substring          string            // "substrings-match"
	Usage              string            // "usage"
	Extensions         map[int]Extension // --
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypeDescription) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID + ` `
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`SUP`, r.SuperType)
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

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r AttributeTypeDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
SuperChain returns an instance of [AttributeTypeDescriptions], which will
contain zero (0) or more slices of [AttributeTypeDescription], each of which
representing an ascending superior type of the receiver instance.

The input classes instance should represent the [AttributeTypeDescriptions]
instance obtained through a [SubschemaSubentry] instance.
*/
func (r AttributeTypeDescription) SuperChain(types AttributeTypeDescriptions) (supers AttributeTypeDescriptions) {
	if &r != nil {
		supers = r.superChain(types)
	}

	return
}

func (r AttributeTypeDescription) superChain(types AttributeTypeDescriptions) (supers AttributeTypeDescriptions) {
	if len(r.SuperType) != 0 {
		supers = make(AttributeTypeDescriptions, 0)
		sup, idx := types.Get(r.SuperType)
		if idx != -1 {
			supers = append(supers, sup)
			x := sup.SuperChain(types)
			for i := 0; i < x.Len(); i++ {
				supers = append(supers, x[i])
			}
		}
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r AttributeTypeDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r AttributeTypeDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
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
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r AttributeTypeDescription) Valid() bool {
	_, oerr := marshalNumericOID(r.NumericOID)
	result := oID(r.SuperType)

	_, xerr := marshalNumericOID(r.Syntax)

	return oerr == nil &&
		(result.True() || xerr == nil) &&
		!(r.Collective && r.Single)
}

/*
MatchingRuleUseDescriptions implements [§ 4.2.4 of RFC 4512] and contains slices of
[MatchingRuleUseDescription].

[§ 4.2.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.4
*/
type MatchingRuleUseDescriptions []MatchingRuleUseDescription

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUseDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		if def := r[i].String(); def != "" {
			s += r.Type() + `: ` + r[i].String() + string(rune(10))
		}
	}

	return
}

/*
Get returns an instance of [MatchingRuleUseDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [MatchingRuleUseDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRuleUseDescriptions) Get(term string) (def MatchingRuleUseDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.8" per [§ 4.2.4 of RFC 4512].

[§ 4.2.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.4
*/
func (r MatchingRuleUseDescriptions) OID() string { return `2.5.21.8` }

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
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`APPLIES`, r.Applies)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r MatchingRuleUseDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r MatchingRuleUseDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r MatchingRuleUseDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r MatchingRuleUseDescription) Valid() bool {
	_, err := marshalNumericOID(r.NumericOID)

	var bogusNumber int
	if len(r.Applies) == 0 {
		bogusNumber++
	}

	for _, at := range r.Applies {
		if !oID(at).True() {
			bogusNumber++
		}
	}

	return err == nil && bogusNumber == 0
}

/*
ObjectClassDescriptions implements [§ 4.2.1 of RFC 4512] and contains slices of
[ObjectClassDescription].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
type ObjectClassDescriptions []ObjectClassDescription

/*
OID returns the numeric OID literal "2.5.21.6" per [§ 4.2.1 of RFC 4512].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
func (r ObjectClassDescriptions) OID() string { return `2.5.21.6` }

/*
ObjectClassIndex returns the Nth [ObjectClassDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) ObjectClassByIndex(idx int) (def ObjectClassDescription) {
	if 0 <= idx && idx < r.ObjectClassDescriptions.Len() {
		def = r.ObjectClassDescriptions[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r ObjectClassDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [ObjectClassDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [ObjectClassDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r ObjectClassDescriptions) Get(term string) (def ObjectClassDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
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
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`SUP`, r.SuperClasses)
		def += stringClassKind(r.Kind)
		def += definitionMVDescriptors(`MUST`, r.Must)
		def += definitionMVDescriptors(`MAY`, r.May)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r ObjectClassDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
SuperChain returns an instance of [ObjectClassDescriptions], which will
contain zero (0) or more slices of [ObjectClassDescription], each of which
representing a direct superior class of the receiver instance.

The input classes instance should represent the [ObjectClassDescriptions]
instance obtained through a [SubschemaSubentry] instance.
*/
func (r ObjectClassDescription) SuperChain(classes ObjectClassDescriptions) (supers ObjectClassDescriptions) {
	for _, class := range r.SuperClasses {
		if def, idx := classes.Get(class); idx != -1 {
			supers = append(supers, def)
		}
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r ObjectClassDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r ObjectClassDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
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

func definitionDescription(desc string) (def string) {
	if len(desc) > 0 {
		def += ` DESC '` + desc + `'`
	}

	return
}

func definitionName(name []string) (def string) {
	switch len(name) {
	case 0:
	default:
		if len(name) > 0 {
			def += ` NAME ` + stringQuotedDescrs(name)
		}
	}

	return
}

func definitionMVDescriptors(key string, src any) (clause string) {
	switch tv := src.(type) {
	case string:
		if len(tv) > 0 {
			clause += ` ` + uc(key) + ` ` + tv
		}
	case []string:
		if len(tv) > 0 {
			clause += ` ` + uc(key) + ` ` + stringDescrs(tv, ` $ `)
		}
	}

	return
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r ObjectClassDescription) Valid() bool {
	_, err := marshalNumericOID(r.NumericOID)

	var bogusNumber int
	if !(uint8(0) <= r.Kind && r.Kind <= uint8(2)) {
		bogusNumber++
	}

	for _, slices := range [][]string{
		r.SuperClasses,
		r.Must,
		r.May,
	} {
		for _, at := range slices {
			if result := oID(at); !result.True() {
				bogusNumber++
			}
		}
	}

	return err == nil && bogusNumber == 0
}

/*
AllMust returns an [AttributeTypeDescriptions] instance containing zero (0)
or more MANDATORY [AttributeTypeDescription] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered [AttributeTypeDescription]
slice instances known to be registered within the relevant [SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
[ObjectClassDescription] instances known to be registered within that same
[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClassDescription) AllMust(types AttributeTypeDescriptions,
	classes ObjectClassDescriptions) (must AttributeTypeDescriptions) {
	must = make(AttributeTypeDescriptions, 0)

	// Add MANDATORY types declared by super classes.
	for i := 0; i < len(r.SuperClasses); i++ {
		sm := r.SuperClasses[i]
		if class, idx := classes.Get(sm); idx != -1 {
			if sc := class.AllMust(types, classes); sc.Len() > 0 {
				must = append(must, sc...)
			}
		}
	}

	// Add local MANDATORY types.
	for i := 0; i < len(r.Must); i++ {
		if attr, idx := types.Get(r.Must[i]); idx != -1 {
			must = append(must, attr)
		}
	}

	return
}

/*
AllMay returns an [AttributeTypeDescriptions] instance containing zero (0)
or more OPTIONAL [AttributeTypeDescription] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered [AttributeTypeDescription]
slice instances known to be registered within the relevant [SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
[ObjectClassDescription] instances known to be registered within that same
[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClassDescription) AllMay(types AttributeTypeDescriptions,
	classes ObjectClassDescriptions) (may AttributeTypeDescriptions) {
	may = make(AttributeTypeDescriptions, 0)

	// Add MANDATORY types declared by super classes.
	for i := 0; i < len(r.SuperClasses); i++ {
		sm := r.SuperClasses[i]
		if class, idx := classes.Get(sm); idx != -1 {
			if sc := class.AllMay(types, classes); sc.Len() > 0 {
				may = append(may, sc...)
			}
		}
	}

	// Add local MANDATORY types.
	for i := 0; i < len(r.May); i++ {
		if attr, idx := types.Get(r.May[i]); idx != -1 {
			may = append(may, attr)
		}
	}

	return
}

/*
DITContentRuleDescriptions implements [§ 4.2.6 of RFC 4512] and contains slices of
[DITContentRuleDescription].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
type DITContentRuleDescriptions []DITContentRuleDescription

/*
OID returns the numeric OID literal "2.5.21.2" per [§ 4.2.6 of RFC 4512].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
func (r DITContentRuleDescriptions) OID() string { return `2.5.21.2` }

/*
DITContentRuleIndex returns the Nth [DITContentRuleDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) DITContentRuleByIndex(idx int) (def DITContentRuleDescription) {
	if 0 <= idx && idx < r.DITContentRuleDescriptions.Len() {
		def = r.DITContentRuleDescriptions[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITContentRuleDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [DITContentRuleDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [DITContentRuleDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITContentRuleDescriptions) Get(term string) (def DITContentRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
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
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`AUX`, r.Aux)
		def += definitionMVDescriptors(`MUST`, r.Must)
		def += definitionMVDescriptors(`MAY`, r.May)
		def += definitionMVDescriptors(`NOT`, r.Not)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r DITContentRuleDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r DITContentRuleDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r DITContentRuleDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r DITContentRuleDescription) Valid() bool {
	// ensure numeric OID is valid
	_, err := marshalNumericOID(r.NumericOID)

	var bogusNumber int
	for _, slices := range [][]string{
		r.Aux,
		r.Must,
		r.May,
		r.Not,
	} {
		for _, o := range slices {
			// ensure o is a valid numeric OID
			// or descriptor.
			if result := oID(o); !result.True() {
				bogusNumber++
			}
		}
	}

	// Make sure MUST and MAY attributes
	// do not appear in NOT clause.
	for _, slices := range [][]string{
		r.Must,
		r.May,
	} {
		for _, at := range slices {
			if strInSlice(at, r.Not) {
				bogusNumber++
			}
		}
	}

	return err == nil && bogusNumber == 0
}

/*
NameFormDescriptions implements [§ 4.2.8 of RFC 4512] and contains slices of
[NameFormDescription].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
type NameFormDescriptions []NameFormDescription

/*
OID returns the numeric OID literal "2.5.21.7" per [§ 4.2.8 of RFC 4512].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
func (r NameFormDescriptions) OID() string { return `2.5.21.7` }

/*
NameFormIndex returns the Nth [NameFormDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) NameFormByIndex(idx int) (def NameFormDescription) {
	if 0 <= idx && idx < r.NameFormDescriptions.Len() {
		def = r.NameFormDescriptions[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r NameFormDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [NameFormDescription] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [NameFormDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r NameFormDescriptions) Get(term string) (def NameFormDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
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
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`OC`, r.OC)
		def += definitionMVDescriptors(`MUST`, r.Must)
		def += definitionMVDescriptors(`MAY`, r.May)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
numeric OID is returned instead.
*/
func (r NameFormDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r NameFormDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's NumericOID or Name value.

Case is not significant in the matching process.
*/
func (r NameFormDescription) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r NameFormDescription) Valid() bool {
	// ensure numeric OID is valid
	_, err := marshalNumericOID(r.NumericOID)
	ocres := oID(r.OC)

	var bogusNumber int
	for _, slices := range [][]string{
		r.Must,
		r.May,
	} {
		for _, o := range slices {
			// ensure o is a valid numeric OID
			// or descriptor.
			if result := oID(o); !result.True() {
				bogusNumber++
			}
		}
	}

	// Make sure MUST and MAY attributes
	// do not overlap. This is fine for
	// classes, but not name forms.
	for _, at := range r.May {
		if strInSlice(at, r.Must) {
			bogusNumber++
		}
	}

	return ocres.True() && err == nil && bogusNumber == 0
}

/*
DITStructureRuleDescriptions implements [§ 4.2.7 of RFC 4512] and contains slices of
[DITStructureRuleDescription].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
type DITStructureRuleDescriptions []DITStructureRuleDescription

/*
OID returns the numeric OID literal "2.5.21.1" per [§ 4.2.7 of RFC 4512].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
func (r DITStructureRuleDescriptions) OID() string { return `2.5.21.1` }

/*
DITStructureRuleIndex returns the Nth [DITStructureRuleDescription] instances found
within the receiver instance.
*/
func (r SubschemaSubentry) DITStructureRuleByIndex(idx int) (def DITStructureRuleDescription) {
	if 0 <= idx && idx < r.DITStructureRuleDescriptions.Len() {
		def = r.DITStructureRuleDescriptions[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITStructureRuleDescriptions) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		s += r.Type() + `: ` + r[i].String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of [DITStructureRuleDescription] and a slice index following
a descriptor or integer identifier match attempt. A zero instance of [DITStructureRuleDescription]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITStructureRuleDescriptions) Get(term string) (def DITStructureRuleDescription, idx int) {
	idx = -1
	for i := 0; i < r.Len(); i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
			break
		}
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
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`FORM`, r.Form)
		def += definitionMVDescriptors(`SUP`, r.SuperRules)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
SubRules returns an instance of [DITStructureRuleDescriptions], each
slice representing a subordinate [DITStructureRuleDescription] of the receiver
instance.
*/
func (r DITStructureRuleDescription) SubRules(rules DITStructureRuleDescriptions) (sub DITStructureRuleDescriptions) {
	for i := 0; i < len(rules); i++ {
		if strInSlice(r.RuleID, rules[i].SuperRules) {
			sub = append(sub, rules[i])
		}
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
integer identifier (RuleID) is returned instead.
*/
func (r DITStructureRuleDescription) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.RuleID
	}

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r DITStructureRuleDescription) XOrigin() (origins []string) {
	for _, ext := range r.Extensions {
		if streqf(ext.XString, `X-ORIGIN`) && len(ext.Values) > 0 {
			origins = ext.Values
			break
		}
	}

	return
}

/*
Match returns a Boolean value indicative of a match between the input string
term value and the receiver's integer rule identifier (RuleID) or Name value.

Case is not significant in the matching process.
*/
func (r DITStructureRuleDescription) Match(term string) bool {
	return term == uitoa(r.RuleID) || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r DITStructureRuleDescription) Valid() bool {
	// ensure integer identifier
	// (rule ID) is valid
	num := isUnsignedNumber(r.RuleID)

	// similarly ensure each super rule
	// is a valid integer identifier.
	var bogusNumber int
	for _, rule := range r.SuperRules {
		if !isUnsignedNumber(rule) {
			bogusNumber++
		}
	}

	return oID(r.Form).True() && num && bogusNumber == 0
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
			if tpfx := uc(token); hasPfx(tpfx, "X-") {
				def.Extensions[len(def.Extensions)] = Extension{
					XString: tpfx,
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
		for t.pos < len(t.input) && (t.input[t.pos] != '\'' ||
			(t.pos > start && t.input[t.pos-1] == '\\')) {
			t.pos++
		}
		t.pos++
	} else if t.input[t.pos] == '(' || t.input[t.pos] == ')' {
		t.pos++
	} else {
		for t.pos < len(t.input) && !isSpace(t.input[t.pos]) &&
			t.input[t.pos] != '(' && t.input[t.pos] != ')' {
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
		}
	}

	return input
}

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.54" per
[§ 3.3.1 of RFC 4517].

[§ 3.3.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.1
*/
func (r LDAPSyntaxDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.54` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.30" per
[§ 3.3.19 of RFC 4517].

[§ 3.3.19 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.19
*/
func (r MatchingRuleDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.30` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.3" per
[§ 3.3.1 of RFC 4517].

[§ 3.3.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.1
*/
func (r AttributeTypeDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.3` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.31" per
[§ 3.3.20 of RFC 4517].

[§ 3.3.20 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.20
*/
func (r MatchingRuleUseDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.31` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.37" per
[§ 3.3.24 of RFC 4517].

[§ 3.3.24 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.24
*/
func (r ObjectClassDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.37` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.16" per
[§ 3.3.7 of RFC 4517].

[§ 3.3.7 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.7
*/
func (r DITContentRuleDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.16` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.35" per
[§ 3.3.22 of RFC 4517].

[§ 3.3.22 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.22
*/
func (r NameFormDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.35` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.17" per
[§ 3.3.8 of RFC 4517].

[§ 3.3.8 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.8
*/
func (r DITStructureRuleDescription) OID() string { return `1.3.6.1.4.1.1466.115.121.1.17` }

func (r LDAPSyntaxDescriptions) Len() int       { return len(r) }
func (r MatchingRuleDescriptions) Len() int     { return len(r) }
func (r AttributeTypeDescriptions) Len() int    { return len(r) }
func (r MatchingRuleUseDescriptions) Len() int  { return len(r) }
func (r ObjectClassDescriptions) Len() int      { return len(r) }
func (r DITContentRuleDescriptions) Len() int   { return len(r) }
func (r NameFormDescriptions) Len() int         { return len(r) }
func (r DITStructureRuleDescriptions) Len() int { return len(r) }

func (r LDAPSyntaxDescriptions) Type() string       { return headerTokens[0] }
func (r MatchingRuleDescriptions) Type() string     { return headerTokens[2] }
func (r AttributeTypeDescriptions) Type() string    { return headerTokens[4] }
func (r MatchingRuleUseDescriptions) Type() string  { return headerTokens[6] }
func (r ObjectClassDescriptions) Type() string      { return headerTokens[8] }
func (r DITContentRuleDescriptions) Type() string   { return headerTokens[10] }
func (r NameFormDescriptions) Type() string         { return headerTokens[12] }
func (r DITStructureRuleDescriptions) Type() string { return headerTokens[14] }

func (r LDAPSyntaxDescription) Type() string       { return headerTokens[1] }
func (r MatchingRuleDescription) Type() string     { return headerTokens[3] }
func (r AttributeTypeDescription) Type() string    { return headerTokens[5] }
func (r MatchingRuleUseDescription) Type() string  { return headerTokens[7] }
func (r ObjectClassDescription) Type() string      { return headerTokens[9] }
func (r DITContentRuleDescription) Type() string   { return headerTokens[11] }
func (r NameFormDescription) Type() string         { return headerTokens[13] }
func (r DITStructureRuleDescription) Type() string { return headerTokens[15] }

func (r LDAPSyntaxDescription) isDefinition()       {}
func (r MatchingRuleDescription) isDefinition()     {}
func (r AttributeTypeDescription) isDefinition()    {}
func (r MatchingRuleUseDescription) isDefinition()  {}
func (r ObjectClassDescription) isDefinition()      {}
func (r DITContentRuleDescription) isDefinition()   {}
func (r NameFormDescription) isDefinition()         {}
func (r DITStructureRuleDescription) isDefinition() {}

func (r LDAPSyntaxDescriptions) isDefinitions()       {}
func (r MatchingRuleDescriptions) isDefinitions()     {}
func (r AttributeTypeDescriptions) isDefinitions()    {}
func (r MatchingRuleUseDescriptions) isDefinitions()  {}
func (r ObjectClassDescriptions) isDefinitions()      {}
func (r DITContentRuleDescriptions) isDefinitions()   {}
func (r NameFormDescriptions) isDefinitions()         {}
func (r DITStructureRuleDescriptions) isDefinitions() {}

// Keep plurals before singulars for optimal matching. Note that
// the respective indices correlate to the return values of the
// Type method held by collection and definition description types.
var headerTokens []string = []string{
	"ldapSyntaxes", "ldapSyntax",
	"matchingRules", "matchingRule",
	"attributeTypes", "attributeType",
	"matchingRuleUses", "matchingRuleUse",
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
