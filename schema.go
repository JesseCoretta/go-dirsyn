package dirsyn

/*
schema.go implements much of Section 4 of RFC 4512.
*/

import (
	"io/fs"
	"path/filepath"
	"sync"
)

/*
NewSubschemaSubentry returns a freshly initialized instance of
*[SubschemaSubentry]. Instances of this type serve as a platform
upon which individual textual definitions may be parsed into
usable instances of [SchemaDefinition].

The prime variadic argument controls whether to prime, or "pre-load",
standard [LDAPSyntax] and [MatchingRule] definitions sourced from RFC
4512, RFC 4523 and RFC 2307 into the receiver instance. The default
is false, which results in no such definitions being pre-loaded.
*/
func (r RFC4512) SubschemaSubentry(prime ...bool) (sch *SubschemaSubentry) {
	sch = &SubschemaSubentry{
		lock: &sync.Mutex{},
	}

	if len(prime) > 0 {
		if prime[0] {
			sch.primeBuiltIns()
		}
	}

	return
}

/*
ReadDirectory recurses all files and folders specified at 'dir',
returning parsed schema bytes (content) alongside an error.

Only files with an extension of ".schema" will be parsed, but all
subdirectories will be traversed in search of these files. Files
not bearing the ".schema" extension will be silently ignored.

File and directory naming schemes MUST guarantee the appropriate
ordering of any and all sub types, sub rules and sub classes which
would rely on the presence of dependency definitions (e.g.: 'cn'
cannot exist without 'name').
*/
func (r *SubschemaSubentry) ReadDirectory(dir string) (err error) {

	// remove any number of trailing
	// slashes from dir.
	dir = trimR(dir, `/`)

	// avoid panicking if the directory does not exist during
	// the "walking" process.
	if _, err = ostat(dir); erris(err, errNotExist) {
		return
	}

	// recurse dir path
	err = filepath.Walk(dir, func(p string, d fs.FileInfo, err error) error {
		if !d.IsDir() && hasSfx(d.Name(), ".schema") {
			err = r.ReadFile(p)
		}

		return err
	})

	return
}

/*
ReadFile returns an error following an attempt to read the
specified filename into an instance of []byte, which is then
fed to the [SubschemaSubentry.ReadBytes] method automatically.

The filename MUST end in ".schema", else an error shall be raised.
*/
func (r *SubschemaSubentry) ReadFile(file string) (err error) {
	if !hasSfx(file, `.schema`) {
		err = errorTxt("Filename MUST end in `.schema`")
		return
	}

	var data []byte
	if data, err = readFile(file); err == nil {
		err = r.ReadBytes(data)
	}

	return
}

/*
ReadBytes returns an error following an attempt parse data ([]byte)
into the receiver instance. This method exists as a convenient
alternative to manual parsing of individual definitions, one at a
time.

Definitions which are dependencies of other definitions should be
parsed first. For example, the following AttributeTypeDescriptions
should be parsed in the order shown:

attributeType ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType ( 2.5.4.3 NAME 'cn' SUP name )

... as "cn" depends upon "name".

Each definition MUST begin with one (1) of the following keywords:

  - "ldapSyntax" or "ldapSyntaxes"
  - "matchingRule" or "matchingRules"
  - "attributeType" or "attributeTypes"
  - "objectClass" or "objectClasses"
  - "dITContentRule" or "dITContentRules"
  - "nameForm" or "nameForms"
  - "dITStructureRule" or "dITStructureRules"

Case is not significant in the keyword matching process.
*/
func (r *SubschemaSubentry) ReadBytes(data []byte) error {
	keywords := []string{
		`ldapSyntaxes`, `ldapSyntax`,
		`matchingRules`, `matchingRule`,
		`attributeTypes`, `attributeType`,
		`objectClasses`, `objectClass`,
		`dITContentRules`, `dITContentRule`,
		`nameForms`, `nameForm`,
		`dITStructureRules`, `dITStructureRule`,
	}

	data = removeBashComments(data)
	data = brepAll(data, []byte("$\n"), []byte("$ "))
	lines := bsplit(data, []byte("\n"))

	var (
		result [][]byte
		cur    []byte
	)

	// Returns a boolean and the keyword IF said
	// keyword is at the start of the line.
	isKeywordLine := func(line []byte) (bool, string) {
		for _, keyword := range keywords {
			if bhasPfx(blc(line), blc([]byte(keyword))) {
				return true, keyword
			}
		}
		return false, ""
	}

	for _, line := range lines {
		line = []byte(condenseWHSP(line))
		if len(line) == 0 {
			continue
		}

		if isKeyword, _ := isKeywordLine(line); isKeyword {
			if len(cur) > 0 {
				result = append(result, cur)
			}
			cur = line
		} else {
			if len(cur) > 0 {
				cur = append(cur, ' ')
				cur = append(cur, line...)
			}
		}
	}

	// Add the final segment
	if len(cur) > 0 {
		result = append(result, cur)
	}

	return r.registerSchemaByCase(result)
}

func (r *SubschemaSubentry) Push(defs ...SchemaDefinition) {
	r.push(false, defs...)
}

func (r *SubschemaSubentry) push(internal bool, defs ...SchemaDefinition) {
	r.lock.Lock()
	defer r.lock.Unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		switch tv := def.(type) {
		case LDAPSyntax:
			r.LDAPSyntaxes.Push(tv)
		case MatchingRule:
			r.MatchingRules.Push(tv)
		case AttributeType:
			r.AttributeTypes.Push(tv)
		case MatchingRuleUse:
			if internal {
				r.MatchingRuleUses = append(r.MatchingRuleUses, tv)
			}
		case ObjectClass:
			r.ObjectClasses.Push(tv)
		case DITContentRule:
			r.DITContentRules.Push(tv)
		case NameForm:
			r.NameForms.Push(tv)
		case DITStructureRule:
			r.DITStructureRules.Push(tv)
		}
	}
}

/*
Unregister returns an error following an attempt to unregister one
or more [SchemaDefinition] qualifier instances.

Note that [MatchingRuleUse] instances cannot be unregistered directly.
Instead, one must unregister the associated [MatchingRule] instance
to accomplish this.
*/
func (r *SubschemaSubentry) Unregister(defs ...SchemaDefinition) (err error) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		switch tv := def.(type) {
		case LDAPSyntax:
			err = r.UnregisterLDAPSyntax(tv)
		case MatchingRule:
			err = r.UnregisterMatchingRule(tv)
		case AttributeType:
			err = r.UnregisterAttributeType(tv)
		case ObjectClass:
			err = r.UnregisterObjectClass(tv)
		case DITContentRule:
			err = r.UnregisterDITContentRule(tv)
		case NameForm:
			err = r.UnregisterNameForm(tv)
		case DITStructureRule:
			err = r.UnregisterDITStructureRule(tv)
		}

		if err != nil {
			// Since this method is variadic, be nice
			// and include the name or numeric OID of
			// the definition which raised an error.
			err = errorTxt(def.Identifier() + " " + err.Error())
			break
		}
	}

	return
}

func (r *SubschemaSubentry) registerSchemaByCase(defs [][]byte) (err error) {
	for i := 0; i < len(defs) && err == nil; i++ {
		def := defs[i]
		if bhasPfx(blc(def), []byte(`ldapsyntax`)) {
			err = r.RegisterLDAPSyntax(def)
		} else if bhasPfx(blc(def), []byte(`matchingrule`)) &&
			!bhasPfx(blc(def), []byte(`matchingruleuse`)) {
			err = r.RegisterMatchingRule(def)
		} else if bhasPfx(blc(def), []byte(`attributetype`)) {
			err = r.RegisterAttributeType(def)
		} else if bhasPfx(blc(def), []byte(`objectclass`)) {
			err = r.RegisterObjectClass(def)
		} else if bhasPfx(blc(def), []byte(`ditcontentrule`)) {
			err = r.RegisterDITContentRule(def)
		} else if bhasPfx(blc(def), []byte(`nameform`)) {
			err = r.RegisterNameForm(def)
		} else if bhasPfx(blc(def), []byte(`ditstructurerule`)) {
			err = r.RegisterDITStructureRule(def)
		} else {
			err = errorTxt("Invalid definition: " + string(def))
		}
	}

	return
}

/*
EffectiveEquality returns an instance of (EQUALITY) [MatchingRule] which reflects
the effective matchingRule honored by the input [AttributeType] instance, whether
direct or by way of a super type in the super chain.

If the input [AttributeType] instance both possesses its own [MatchingRule] AND is
a subtype of another (valid) [AttributeType] definition, the local [MatchingRule]
has precedence and is returned.
*/
func (r *SubschemaSubentry) EffectiveEquality(at any) (rule MatchingRule) {
	var attr AttributeType
	switch tv := at.(type) {
	case AttributeType:
		attr = tv
	case string:
		attr, _ = r.AttributeTypes.Get(tv)
	default:
		return
	}

	if s := attr.Equality; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.MatchingRules.Get(s)
		return
	} else if u := attr.SuperType; len(u) > 0 {
		if sup, sidx := r.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = r.EffectiveEquality(sup)
		}
	}

	return
}

/*
EffectiveSubstring returns an instance of (SUBSTR) [MatchingRule] which reflects
the effective matchingRule honored by the input [AttributeType] instance, whether
direct or by way of a super type in the super chain.

If the input [AttributeType] instance both possesses its own [MatchingRule] AND is
a subtype of another (valid) [AttributeType] definition, the local [MatchingRule]
has precedence and is returned.
*/
func (r *SubschemaSubentry) EffectiveSubstring(at any) (rule MatchingRule) {
	var attr AttributeType
	switch tv := at.(type) {
	case AttributeType:
		attr = tv
	case string:
		attr, _ = r.AttributeTypes.Get(tv)
	default:
		return
	}

	if s := attr.Substring; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.MatchingRules.Get(s)
		return
	} else if u := attr.SuperType; len(u) > 0 {
		if sup, sidx := r.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = r.EffectiveSubstring(sup)
		}
	}

	return
}

/*
EffectiveOrdering returns an instance of (ORDERING) [MatchingRule] which reflects
the effective matchingRule honored by the input [AttributeType] instance, whether
direct or by way of a super type in the super chain.

If the input [AttributeType] instance both possesses its own [MatchingRule] AND is
a subtype of another (valid) [AttributeType] definition, the local [MatchingRule]
has precedence and is returned.
*/
func (r *SubschemaSubentry) EffectiveOrdering(at any) (rule MatchingRule) {
	var attr AttributeType
	switch tv := at.(type) {
	case AttributeType:
		attr = tv
	case string:
		attr, _ = r.AttributeTypes.Get(tv)
	default:
		return
	}

	if s := attr.Ordering; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.MatchingRules.Get(s)
		return
	} else if u := attr.SuperType; len(u) > 0 {
		if sup, sidx := r.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = r.EffectiveOrdering(sup)
		}
	}

	return
}

/*
EffectiveSyntax returns an instance of [LDAPSyntax] which reflects the effective
syntax honored by the input [AttributeType] instance, whether direct or by way of
a super type in the super chain.

The return instance of [LDAPSyntax] should NEVER be zero, as all [AttributeType]
instances are expected to honor a syntax in some way.

If the input [AttributeType] instance both possesses its own [LDAPSyntax] AND is
a subtype of another (valid) [AttributeType] definition, the local [LDAPSyntax]
has precedence and is returned.
*/
func (r *SubschemaSubentry) EffectiveSyntax(at any) (syntax LDAPSyntax) {
	var attr AttributeType
	switch tv := at.(type) {
	case AttributeType:
		attr = tv
	case string:
		attr, _ = r.AttributeTypes.Get(tv)
	default:
		return
	}

	if s := attr.Syntax; len(s) > 0 {
		// Syntax is honored locally, so use it.
		syntax, _ = r.LDAPSyntaxes.Get(s)
		return
	} else if u := attr.SuperType; len(u) > 0 {
		if sup, sidx := r.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			syntax = r.EffectiveSyntax(sup)
		}
	}

	return
}

/*
SchemaDefinition is an interface type qualified through instances of
the following types:

  - [LDAPSyntax]
  - [MatchingRule]
  - [AttributeType]
  - [MatchingRuleUse]
  - [ObjectClass]
  - [DITContentRule]
  - [NameForm]
  - [DITStructureRule]
*/
type SchemaDefinition interface {
	// OID returns the official ASN.1 OBJECT IDENTIFIER
	// (numeric OID) belonging to the underlying TYPE --
	// NOT the individual definition's assigned OID (see
	// the NumericOID struct field).
	OID() string

	// IsZero returns a Boolean value indicative of a nil
	// receiver state.
	IsZero() bool

	// Identifier returns the receiver's descriptor OR
	// (if one was not set) its numeric OID.
	Identifier() string

	// Type returns the string type name of the receiver
	// instance (e.g.: "attributeType").
	Type() string

	// Valid returns a Boolean value indicative of a valid
	// receiver state.
	Valid() bool

	// String returns the string representation of the
	// receiver instance.
	String() string

	// XOrigin returns slices of standard names, which may
	// be RFCs, Internet-Drafts or ITU-T Recommendations,
	// from which the receiver originates.
	XOrigin() []string

	// Differentiate from other interfaces.
	isDefinition()
}

/*
SchemaDefinitions is an interface type qualified through instances
of the following types:

  - [LDAPSyntaxes]
  - [MatchingRules]
  - [AttributeTypes]
  - [MatchingRuleUses]
  - [ObjectClasses]
  - [DITContentRules]
  - [NameForms]
  - [DITStructureRules]

It is generally discouraged to modify instances of the above types
directly due to thread safety concerns; instead, perform modifications
via the appropriate instance of the [SubschemaSubentry] type.
*/
type SchemaDefinitions interface {
	// Len returns the integer length of the receiver instance.
	Len() int

	// OID returns the official ASN.1 OBJECT IDENTIFIER
	// (numeric OID) belonging to the underlying TYPE.
	OID() string

	// Type returns the string type name of the receiver
	// instance (e.g.: "attributeTypes").
	Type() string

	// IsZero returns a Boolean value indicative of a nil
	// receiver state.
	IsZero() bool

	// String returns the string representation of the
	// receiver instance.
	String() string

	// Contains returns an integer index value indicative
	// of whether the specified SchemaDefinition -- identified
	// by descriptor or numeric OID -- resides within
	// the receiver instance and what what numerical index.
	//
	// In the event of an instance of LDAPSyntaxes,
	// the description is used in place of a descriptor,
	// and can be matched regardless of whitespace or
	// case folding.
	//
	// In the event of an instance of DITStructureRule,
	// an integer identifier (rule ID) may be used in
	// place of a numeric OID.
	//
	// If a particular search term is not found, -1 is
	// subsequently returned.
	Contains(string) int

	// Push appends a SchemaDefinition instance into the
	// receiver instance. Uniqueness checks are conducted
	// automatically using the numeric OID (or rule ID in
	// the case of a DITStructureRule).
	Push(...SchemaDefinition)

	// Differentiate from other interfaces.
	isDefinitions()
}

/*
SubschemaSubentry implements [§ 4.2 of RFC 4512] and contains slice types
of various [SchemaDefinition] types.

Instances of this type are thread safe by way of an internal instance
of [sync/Mutex]. No special actions are required by users to make use
of this feature, and its invocation is automatic wherever appropriate.

[§ 4.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2
*/
type SubschemaSubentry struct {
	LDAPSyntaxes
	MatchingRules
	AttributeTypes
	MatchingRuleUses
	ObjectClasses
	DITContentRules
	NameForms
	DITStructureRules

	lock *sync.Mutex
}

/*
primeBuiltIns is a private method used to pre-load standard LDAPSyntax
and MatchingRule instances sourced from formalized RFCs.
*/
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

	ssse += r.LDAPSyntaxes.String()
	ssse += r.MatchingRules.String()
	ssse += r.AttributeTypes.String()
	ssse += r.MatchingRuleUses.String()
	ssse += r.ObjectClasses.String()
	ssse += r.DITContentRules.String()
	ssse += r.NameForms.String()
	ssse += r.DITStructureRules.String()

	// remove final newline present.
	ssse = trim(ssse, string(rune(10)))

	return
}

func assertLDAPSyntax(x any) (def LDAPSyntax, err error) {
	switch tv := x.(type) {
	case LDAPSyntax:
		def = tv
	default:
		def, err = marshalLDAPSyntax(tv)
	}

	return
}

/*
RegisterLDAPSyntax returns an error following an attempt to add a new syntax
definition to the receiver instance.

Valid input types may be an instance of [LDAPSyntax], or its equivalent string
representation (LDAPSyntaxDescription) as described in [§ 4.1.5 of RFC 4512].

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
func (r *SubschemaSubentry) RegisterLDAPSyntax(input any) (err error) {
	var def LDAPSyntax
	if def, err = assertLDAPSyntax(input); err != nil {
		return
	}

	if _, idx := r.LDAPSyntax(def.NumericOID); idx != -1 {
		err = errorTxt("ldapSyntax: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	if !def.Valid() {
		err = errorTxt("ldapSyntax: Invalid description syntax")
		return
	}

	r.Push(def)

	return
}

func (r *SubschemaSubentry) ldapSyntaxDepScan(def LDAPSyntax) (err error) {
	for i := 0; i < r.MatchingRules.Len(); i++ {
		if cand := r.MatchingRules[i]; cand.Syntax == def.NumericOID {
			err = errorTxt(def.Type() + " has matchingRule dependents")
			return
		}
	}

	for i := 0; i < r.AttributeTypes.Len(); i++ {
		if cand := r.AttributeTypes[i]; cand.Syntax == def.NumericOID {
			err = errorTxt(def.Type() + " has attributeType dependents")
			break
		}
	}

	return
}

/*
UnregisterLDAPSyntax returns an error following an attempt to remove the
specified definition from the receiver instance. A successful run will also
remove the associated [MatchingRuleUse] instance.

Valid input types may be an instance of [LDAPSyntax], or its equivalent string
representation (LDAPSyntaxDescription) as described in [§ 4.1.5 of RFC 4512].

Note that this process shall fail if the specified definition has dependent
matchingRule or attributeType definitions.

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
func (r *SubschemaSubentry) UnregisterLDAPSyntax(input any) (err error) {
	var def LDAPSyntax
	if def, err = assertLDAPSyntax(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.LDAPSyntaxes.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.ldapSyntaxDepScan(def); err == nil {
		r.LDAPSyntaxes = append(r.LDAPSyntaxes[:idx],
			r.LDAPSyntaxes[idx+1:]...)
	}

	return
}

func assertMatchingRule(x any) (def MatchingRule, err error) {
	switch tv := x.(type) {
	case MatchingRule:
		def = tv
	default:
		def, err = marshalMatchingRule(tv)
	}

	return
}

/*
RegisterMatchingRule returns an error following an attempt to add a new matchingRule
definition to the receiver instance.

Valid input types may be an instance of [MatchingRule], or its equivalent string
representation (MatchingRuleDescription) as described in [§ 4.1.3 of RFC 4512].

[§ 4.1.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3
*/
func (r *SubschemaSubentry) RegisterMatchingRule(input any) (err error) {
	var def MatchingRule
	if def, err = assertMatchingRule(input); err != nil {
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

	r.Push(def)
	r.push(true, mru)

	return
}

func (r *SubschemaSubentry) matchingRuleDepScan(def MatchingRule) (err error) {
	// First check to see if an associated matchingRuleUse
	// instance exists AND still has users...
	mru, idx := r.MatchingRuleUses.Get(def.NumericOID)
	if idx != -1 && len(mru.Applies) > 0 {
		err = errorTxt(def.Type() + " has matchingRuleUse dependents")
		return
	}

	// Next check to see if the matchingRule instance
	// exists AND is used by any attributeType instances
	// for EQUALITY, ORDERING or SUBSTR.
	for i := 0; i < r.AttributeTypes.Len() && err == nil; i++ {
		for _, mrt := range []string{
			r.AttributeTypes[i].Equality,
			r.AttributeTypes[i].Ordering,
			r.AttributeTypes[i].Substring,
		} {
			if def.NumericOID == mrt || strInSlice(mrt, def.Name) {
				err = errorTxt(def.Type() + " has attributeType dependents")
				break
			}
		}
	}

	return
}

/*
UnregisterMatchingRule returns an error following an attempt to remove the
specified definition from the receiver instance. A successful run will also
remove the associated [MatchingRuleUse] instance.

Valid input types may be an instance of [MatchingRule], or its equivalent string
representation (MatchingRuleDescription) as described in [§ 4.1.3 of RFC 4512].

Note that this process shall fail if the specified definition has dependent
attributeType definitions, as well as if any matchingRuleUse instances exist
with one or more applied types.

[§ 4.1.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3
*/
func (r *SubschemaSubentry) UnregisterMatchingRule(input any) (err error) {
	var def MatchingRule
	if def, err = assertMatchingRule(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.MatchingRules.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.matchingRuleDepScan(def); err == nil {
		_, uidx := r.MatchingRuleUses.Get(def.NumericOID)
		r.MatchingRuleUses = append(r.MatchingRuleUses[:uidx],
			r.MatchingRuleUses[uidx+1:]...)
		r.MatchingRules = append(r.MatchingRules[:idx],
			r.MatchingRules[idx+1:]...)
	}

	return
}

/*
RegisterAttributeType returns an error following an attempt to add a new [AttributeType]
definition to the receiver instance.

Valid input types may be an instance of [AttributeType], or its equivalent string
representation (AttributeTypeDescription) as described in [§ 4.1.2 of RFC 4512].

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
*/
func (r *SubschemaSubentry) RegisterAttributeType(input any) (err error) {
	var def AttributeType
	if def, err = assertAttributeType(input); err != nil {
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
			var rule MatchingRule
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

	r.Push(def)
	r.updateMatchingRuleUse(def, mrups)

	return
}

/*
SuperiorType resolves the super type of id to a proper instance of [AttributeType].

The input string id must be the numeric OID or name of the subordinate
attribute type.

Note that if a name is used, case-folding is not significant in the
matching process.

If zero slices are returned, this can mean either the attribute type was
not found, or that it has no super type of its own.
*/
func (r SubschemaSubentry) SuperiorType(id string) (sup AttributeType) {
	if typ, idx := r.AttributeType(id); idx != -1 {
		if typ.SuperType != "" {
			if at, sidx := r.AttributeType(typ.SuperType); sidx != -1 {
				sup = at
			}
		}
	}

	return
}

/*
SubordinateTypes returns slices of [AttributeType], each of which are direct
subordinate types of the input string id.

The input string id must be the numeric OID or name of the supposed superior
type.

Note that if a name is used, case-folding is not significant in the matching
process.

If zero slices are returned, this can mean either the superior type was not
found, or that it has no subordinate types of its own.
*/
func (r SubschemaSubentry) SubordinateTypes(id string) (sub AttributeTypes) {
	if typ, idx := r.AttributeTypes.Get(id); idx != -1 {
		for i := 0; i < r.AttributeTypes.Len(); i++ {
			at := r.AttributeTypes[i]
			if typ.NumericOID == at.SuperType {
				sub.Push(at)
			} else {
				for n := 0; n < len(typ.Name); n++ {
					if typ.Name[n] == at.SuperType {
						sub.Push(at)
					}
				}
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeDepScan(def AttributeType) (err error) {
	if deps := r.SubordinateTypes(def.NumericOID); deps.Len() > 0 {
		err = errorTxt(def.Type() + " has subordinate attributeType dependents")
		return
	}

	for _, err = range []error{
		r.attributeTypeObjectClassDepScan(def),
		r.attributeTypeDITContentRuleDepScan(def),
		r.attributeTypeNameFormDepScan(def),
	} {
		if err != nil {
			break
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeObjectClassDepScan(def AttributeType) (err error) {
	for n := 0; n < r.ObjectClasses.Len(); n++ {
		for _, slice := range [][]string{
			r.ObjectClasses[n].Must,
			r.ObjectClasses[n].May,
		} {
			if strInSlice(def.NumericOID, slice) {
				err = errorTxt(def.Type() + " has objectClass dependents")
				return
			}
			for n := 0; n < len(def.Name); n++ {
				if strInSlice(def.Name[n], slice) {
					err = errorTxt(def.Type() + " has objectClass dependents")
					return
				}
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeDITContentRuleDepScan(def AttributeType) (err error) {
	for n := 0; n < r.DITContentRules.Len(); n++ {
		for _, slice := range [][]string{
			r.DITContentRules[n].Must,
			r.DITContentRules[n].May,
			r.DITContentRules[n].Not,
		} {
			if strInSlice(def.NumericOID, slice) {
				err = errorTxt(def.Type() + " has dITContentRule dependents")
				return
			}
			for n := 0; n < len(def.Name); n++ {
				if strInSlice(def.Name[n], slice) {
					err = errorTxt(def.Type() + " has dITContentRule dependents")
					return
				}
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeNameFormDepScan(def AttributeType) (err error) {
	for n := 0; n < r.NameForms.Len(); n++ {
		for _, slice := range [][]string{
			r.NameForms[n].Must,
			r.NameForms[n].May,
		} {
			if strInSlice(def.NumericOID, slice) {
				err = errorTxt(def.Type() + " has nameForm dependents")
				return
			}
			for n := 0; n < len(def.Name); n++ {
				if strInSlice(def.Name[n], slice) {
					err = errorTxt(def.Type() + " has nameForm dependents")
					return
				}
			}
		}
	}

	return
}

func assertAttributeType(x any) (def AttributeType, err error) {
	switch tv := x.(type) {
	case AttributeType:
		def = tv
	default:
		def, err = marshalAttributeType(tv)
	}

	return
}

/*
UnregisterAttributeType returns an error following an attempt to remove the
specified definition from the receiver instance. A successful run will also
remove the target from any applied [MatchingRuleUse] instances.

Valid input types may be an instance of [AttributeType], or its equivalent string
representation (AttributeTypeDescription) as described in [§ 4.1.2 of RFC 4512].

Note that this process shall fail if the specified definition has dependent
definitions such as nameForm, objectClass or dITContentRule instances.

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
*/
func (r *SubschemaSubentry) UnregisterAttributeType(input any) (err error) {
	var def AttributeType
	if def, err = assertAttributeType(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.AttributeTypes.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.attributeTypeDepScan(def); err == nil {
		r.unregisterMatchingRuleUsers(def)
		r.AttributeTypes = append(r.AttributeTypes[:idx],
			r.AttributeTypes[idx+1:]...)
	}

	return
}

func (r *SubschemaSubentry) unregisterMatchingRuleUsers(def AttributeType) {
	for i := 0; i < r.MatchingRuleUses.Len(); i++ {
		mru := r.MatchingRuleUses[i]
		for a := 0; a < len(mru.Applies); a++ {
			if def.NumericOID == mru.Applies[a] ||
				strInSlice(mru.Applies[a], def.Name) {
				mru.Applies = append(mru.Applies[:a],
					mru.Applies[a+1:]...)
				r.MatchingRuleUses = append(r.MatchingRuleUses[:i],
					r.MatchingRuleUses[i+1:]...)
			}
		}
	}
}

func (r *SubschemaSubentry) updateMatchingRuleUse(def AttributeType, mrups map[string]string) {
	name := def.Identifier()
	// Update appropriate MRUs to include new attr OID
	for _, v := range mrups {
		if _, idx := r.MatchingRuleUse(v); idx != -1 {
			if found := strInSlice(name, r.MatchingRuleUses[idx].Applies); !found {
				r.MatchingRuleUses[idx].Applies =
					append(r.MatchingRuleUses[idx].Applies, name)
			}
		}
	}
}

/*
RegisterObjectClass returns an error following an attempt to add a new objectClass
definition to the receiver instance.

Valid input types may be an instance of [ObjectClass], or its equivalent string
representation (ObjectClassDescription) as described in [§ 4.1.1 of RFC 4512].

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
func (r *SubschemaSubentry) RegisterObjectClass(input any) (err error) {
	var def ObjectClass
	if def, err = assertObjectClass(input); err != nil {
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
		err = errorTxt("objectClass: Invalid description syntax")
		return
	}

	r.Push(def)

	return
}

func (r *SubschemaSubentry) objectClassDepScan(def ObjectClass) (err error) {
	if deps := r.SubordinateClasses(def.NumericOID); deps.Len() > 0 {
		err = errorTxt(def.Type() + " has subordinate objectClass dependents")
	} else if def.Kind == 0 {
		// Scan for dependent nameForm or dITContentRule
		// instances IF the class is STRUCTURAL ...
		for n := 0; n < r.NameForms.Len(); n++ {
			if r.NameForms[n].OC == def.NumericOID ||
				strInSlice(r.NameForms[n].OC, def.Name) {
				err = errorTxt(def.Type() + " has nameForm dependents")
				return
			}
		}
		for d := 0; d < r.DITContentRules.Len(); d++ {
			if r.DITContentRules[d].NumericOID == def.NumericOID {
				err = errorTxt(def.Type() + " has dITContentRule dependents")
				return
			}
		}
	} else if def.Kind == 1 {
		// Scan for dependent dITContentRule
		// instances IF the class is AUXILIARY
		for d := 0; d < r.DITContentRules.Len(); d++ {
			if strInSlice(def.NumericOID, r.DITContentRules[d].Aux) {
				err = errorTxt(def.Type() + " has dITContentRule dependents")
				return
			}
			for n := 0; n < len(def.Name); n++ {
				if strInSlice(def.Name[n], r.DITContentRules[d].Aux) {
					err = errorTxt(def.Type() + " has dITContentRule dependents")
					return
				}
			}
		}
	}

	return
}

/*
UnregisterObjectClass returns an error following an attempt to remove the
specified definition from the receiver instance.

Valid input types may be an instance of [ObjectClass], or its equivalent string
representation (ObjectClassDescription) as described in [§ 4.1.1 of RFC 4512].

Note that this process shall fail if the specified definition has dependent
definitions such as nameForm or dITContentRule instances.

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
func (r *SubschemaSubentry) UnregisterObjectClass(input any) (err error) {
	var def ObjectClass
	if def, err = assertObjectClass(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.ObjectClasses.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.objectClassDepScan(def); err == nil {
		r.ObjectClasses = append(r.ObjectClasses[:idx],
			r.ObjectClasses[idx+1:]...)
	}

	return
}

func (r *SubschemaSubentry) dITContentRuleDepScan(def DITContentRule) (err error) {
	// present only for consistency; dITContentRules
	// are not subject to dependency constraints.
	return
}

/*
RegisterDITContentRule returns an error following an attempt to add a new
[DITContentRule] to the receiver instance.

Valid input types may be an instance of [DITContentRule], or its equivalent
string representation (DITContentRuleDescription) as described in [§ 4.1.6
of RFC 4512].

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
func (r *SubschemaSubentry) RegisterDITContentRule(input any) (err error) {
	var def DITContentRule
	if def, err = assertDITContentRule(input); err != nil {
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
		} else if r.ObjectClasses[idx].Kind != 1 {
			err = errorTxt("dITContentRule: non-AUXILIARY class in AUX clause: '" +
				def.Aux[i] + "'")
			return
		}
	}

	if !def.Valid() {
		err = errorTxt("dITContentRule: Invalid description syntax")
		return
	}

	r.Push(def)

	return
}

/*
UnregisterDITContentRule returns an error following an attempt to remove the specified
definition from the receiver instance.

Valid input types may be an instance of [DITContentRule], or its equivalent string
representation (DITContentRuleDescription) as described in [§ 4.1.6 of RFC 4512].

[DITContentRule] instances are not subject to any dependency constraints.

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
func (r *SubschemaSubentry) UnregisterDITContentRule(input any) (err error) {
	var def NameForm
	if def, err = assertNameForm(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.NameForms.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	r.NameForms = append(r.NameForms[:idx],
		r.NameForms[idx+1:]...)

	return
}

func assertNameForm(x any) (def NameForm, err error) {
	switch tv := x.(type) {
	case NameForm:
		def = tv
	default:
		def, err = marshalNameForm(tv)
	}

	return
}

/*
RegisterNameForm returns an error following an attempt to add a new nameForm
definition to the receiver instance.

Valid input types may be an instance of [NameForm], or its equivalent string
representation (NameFormDescription) as described in [§ 4.1.7.2 of RFC 4512].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
func (r *SubschemaSubentry) RegisterNameForm(input any) (err error) {
	var def NameForm
	if def, err = assertNameForm(input); err != nil {
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

	r.Push(def)

	return
}

func (r *SubschemaSubentry) nameFormDepScan(def NameForm) (err error) {
	for i := 0; i < r.DITStructureRules.Len(); i++ {
		if cand := r.DITStructureRules[i]; cand.Form == def.NumericOID ||
			strInSlice(cand.Form, def.Name) {
			err = errorTxt(def.Type() + " has dITStructureRule dependents")
			break
		}
	}

	return
}

/*
UnregisterNameForm returns an error following an attempt to remove the specified
definition from the receiver instance.

Valid input types may be an instance of [NameForm], or its equivalent string
representation (NameFormDescription) as described in [§ 4.1.7.2 of RFC 4512].

Note that this process shall fail if the specified definition has dependent definitions,
such as instances of [DITStructureRule].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
func (r *SubschemaSubentry) UnregisterNameForm(input any) (err error) {
	var def NameForm
	if def, err = assertNameForm(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.NameForms.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.nameFormDepScan(def); err == nil {
		r.NameForms = append(r.NameForms[:idx],
			r.NameForms[idx+1:]...)
	}

	return
}

/*
UnregisterDITStructureRule returns an error following an attempt to remove the
specified definition from the receiver instance.

Valid input types may be an instance of [DITStructureRule], or its equivalent string
representation (DITStructureRuleDescription) as described in [§ 4.1.7.1 of RFC 4512].

Note that this process shall fail if the specified definition has dependent definitions,
such as subordinate structure rules.

[§ 4.1.7.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1
*/
func (r *SubschemaSubentry) UnregisterDITStructureRule(input any) (err error) {
	var def DITStructureRule
	if def, err = assertDITStructureRule(input); err != nil {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	_, idx := r.DITStructureRules.Get(def.RuleID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	if err = r.dITStructureRuleDepScan(def); err == nil {
		r.DITStructureRules = append(r.DITStructureRules[:idx],
			r.DITStructureRules[idx+1:]...)
	}

	return
}

func (r *SubschemaSubentry) dITStructureRuleDepScan(def DITStructureRule) (err error) {
	if deps := r.SubordinateStructureRules(def.RuleID); deps.Len() > 0 {
		err = errorTxt(def.Type() + " has subordinate dITStructureRule dependents")
	}

	return
}

/*
RegisterDITStructureRule returns an error following an attempt to add a new structure
rule definition to the receiver instance.

Valid input types may be an instance of [DITStructureRule], or its equivalent string
representation (DITStructureRuleDescription) as described in [§ 4.1.7.1 of RFC 4512].

[§ 4.1.7.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1
*/
func (r *SubschemaSubentry) RegisterDITStructureRule(input any) (err error) {
	var def DITStructureRule
	if def, err = assertDITStructureRule(input); err != nil {
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

	r.Push(def)

	return
}

/*
Counters returns an instance of [9]uint, each slice representing the
current number of [SchemaDefinition] instances of a particular collection,
while the final slice represents the sum total of the previous eight (8).

Collection indices are as follows:

  - 0 - "LDAPSyntaxes"
  - 1 - "MatchingRules"
  - 2 - "AttributeTypes"
  - 3 - "MatchingRuleUses"
  - 4 - "ObjectClasses"
  - 5 - "DITContentRules"
  - 6 - "NameForms"
  - 7 - "DITStructureRules"
  - 8 - "total"

As the return type is fixed, there is no risk of panic when calling
indices 0 through 8 in any circumstance.

Note that locking is engaged by this method for the purposes of
thread safe tallying and summation.
*/
func (r *SubschemaSubentry) Counters() (counters [9]uint) {

	r.lock.Lock()
	defer r.lock.Unlock()

	counters[0] = uint(r.LDAPSyntaxes.Len())
	counters[1] = uint(r.MatchingRules.Len())
	counters[2] = uint(r.AttributeTypes.Len())
	counters[3] = uint(r.MatchingRuleUses.Len())
	counters[4] = uint(r.ObjectClasses.Len())
	counters[5] = uint(r.DITContentRules.Len())
	counters[6] = uint(r.NameForms.Len())
	counters[7] = uint(r.DITStructureRules.Len())

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
LDAPSyntax returns an instance of [LDAPSyntax] alongside the associated
integer index. If not found, the index shall be -1 and the definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [LDAPSyntax] numeric OID, or the description text.

Note that if description text is used, neither whitespace nor case-folding
are significant in the matching process.
*/
func (r *SubschemaSubentry) LDAPSyntax(term string) (LDAPSyntax, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.LDAPSyntaxes.Get(term)
}

/*
MatchingRule returns an instance of [MatchingRule] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [MatchingRule] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) MatchingRule(term string) (MatchingRule, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.MatchingRules.Get(term)
}

/*
MatchingRuleUse returns an instance of [MatchingRuleUse] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [MatchingRuleUse] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) MatchingRuleUse(term string) (MatchingRuleUse, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.MatchingRuleUses.Get(term)
}

/*
AttributeType returns an instance of [AttributeType] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [AttributeType] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) AttributeType(term string) (AttributeType, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.AttributeTypes.Get(term)
}

/*
NameForm returns an instance of [NameForm] alongside the associated integer
index. If not found, the index shall be -1 and the schema definition shall
be unpopulated.

The input id value (identifier) should be the string representation of
the desired [NameForm] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) NameForm(term string) (NameForm, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.NameForms.Get(term)
}

/*
DITContentRule returns an instance of [DITContentRule] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [DITContentRule] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) DITContentRule(term string) (DITContentRule, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.DITContentRules.Get(term)
}

/*
DITStructureRule returns an instance of [DITStructureRule] alongside the
associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of
the desired [DITStructureRule] integer identifier (rule ID), or name
(descriptor).

Note that if a name is used, case-folding is not significant in the
matching process.
*/
func (r *SubschemaSubentry) DITStructureRule(term string) (DITStructureRule, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.DITStructureRules.Get(term)
}

/*
SubordinateStructureRules returns slices of [DITStructureRule],
each of which are direct subordinate structure rules of the input string id.

The input string id must be the rule ID or name of the supposed superior
structure rule.

Note that if a name is used, case-folding is not significant in the matching
process.

If zero slices are returned, this can mean either the superior structure rule
was not found, or that it has no subordinate rules of its own.
*/
func (r SubschemaSubentry) SubordinateStructureRules(id string) (sub DITStructureRules) {
	if rule, idx := r.DITStructureRules.Get(id); idx != -1 {
		for i := 0; i < r.DITStructureRules.Len(); i++ {
			// NOTE - don't skip the superior rule itself,
			// as it may be a recursive (self-referencing)
			// structure rule.
			dsr := r.DITStructureRules[i]
			if strInSlice(rule.RuleID, dsr.SuperRules) {
				sub = append(sub, dsr)
			}
		}
	}

	return
}

/*
SuperiorStructureRules returns slices of [DITStructureRule], each of
which are direct superior structure rules of the input string id.

The input string id must be the rule ID or name of the subordinate
structure rule.

Note that if a name is used, case-folding is not significant in the
matching process.

If zero slices are returned, this can mean either the structure rule
was not found, or that it has no superior rules of its own.
*/
func (r SubschemaSubentry) SuperiorStructureRules(id string) (sup DITStructureRules) {
	if rule, idx := r.DITStructureRule(id); idx != -1 {
		for i := 0; i < len(rule.SuperRules); i++ {
			s := rule.SuperRules[i]
			if dsr, sidx := r.DITStructureRule(s); sidx != -1 {
				sup.Push(dsr)
			}
		}
	}

	return
}

/*
NamedObjectClass returns an instance of [ObjectClass] alongside its
associated slice index within the receiver's object class collection.

The input id must be the integer identifier (rule ID) or name of a registered
[DITStructureRule] instance.

The return instance of [ObjectClass] is resolved from the "OC" clause
found within the [NameForm] beared by the [DITStructureRule].

The [ObjectClass], if found, is guaranteed to be of the STRUCTURAL kind.
*/
func (r SubschemaSubentry) NamedObjectClass(id string) (noc ObjectClass, idx int) {
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
func (r LDAPSyntax) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRule) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeType) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleUse) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectClass) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITContentRule) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NameForm) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITStructureRule) IsZero() bool { return &r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r LDAPSyntaxes) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRules) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r AttributeTypes) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r MatchingRuleUses) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r ObjectClasses) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITContentRules) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r NameForms) IsZero() bool { return r.Len() == 0 }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r DITStructureRules) IsZero() bool { return r.Len() == 0 }

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r LDAPSyntaxes) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is an [LDAPSyntax] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [LDAPSyntax.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *LDAPSyntaxes) Push(defs ...LDAPSyntax) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r MatchingRules) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [MatchingRule] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [MatchingRule.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *MatchingRules) Push(defs ...MatchingRule) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r AttributeTypes) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [AttributeType] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [AttributeType.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *AttributeTypes) Push(defs ...AttributeType) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r MatchingRuleUses) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [MatchingRuleUse] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [MatchingRuleUse.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *MatchingRuleUses) Push(defs ...MatchingRuleUse) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r ObjectClasses) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [ObjectClass] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [ObjectClass.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *ObjectClasses) Push(defs ...ObjectClass) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r DITContentRules) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [DITContentRule] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [DITContentRule.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *DITContentRules) Push(defs ...DITContentRule) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r NameForms) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].NumericOID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [NameForm] instance
  - NumericOID of def does not already exist as a slice
  - Execution of [NameForm.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *NameForms) Push(defs ...NameForm) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r DITStructureRules) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].RuleID == id ||
			strInSlice(id, r[i].Name) {
			idx = i
		}
	}

	return
}

/*
Push appends def to the receiver instance if ALL of the following
evaluate as true:

  - def is a [DITStructureRule] instance
  - RuleID of def does not already exist as a slice
  - Execution of [DITStructureRule.Valid] encounters no issues

When executed directly, this method is NOT thread safe; see
[SubschemaSubentry.Push] instead.
*/
func (r *DITStructureRules) Push(defs ...DITStructureRule) {
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.RuleID) == -1 {
			*r = append(*r, def)
		}
	}
}

/*
SuperClassOf returns a Boolean value indicative of r being a superior ("SUP")
[ObjectClass] of sub, which may be a string or bonafide instance of
[ObjectClass].

Note: this will trace all super class chains indefinitely and, thus, will
recognize any superior association without regard for "depth".
*/
func (r ObjectClass) SuperClassOf(sub any, classes ObjectClasses) (sup bool) {
	var subordinate ObjectClass
	switch tv := sub.(type) {
	case string:
		// resolve to ObjectClass
		var idx int
		if subordinate, idx = classes.Get(tv); idx == -1 {
			return
		}
	case ObjectClass:
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
LDAPSyntaxes implements [§ 4.2.5 of RFC 4512] and contains slices of
[LDAPSyntax].

[§ 4.2.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.5
*/
type LDAPSyntaxes []LDAPSyntax

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
Get returns an instance of [LDAPSyntax] and a slice index following
a description or numeric OID match attempt. A zero instance of [LDAPSyntax]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r LDAPSyntaxes) Get(term string) (def LDAPSyntax, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
LDAPSyntaxByIndex returns the Nth [LDAPSyntax] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) LDAPSyntaxByIndex(idx int) (def LDAPSyntax) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.LDAPSyntaxes.Len() {
		def = r.LDAPSyntaxes[idx]
	}

	return
}

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.101.120.16" per
[§ 4.2.5 of RFC 4512].

[§ 4.2.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.5
*/
func (r LDAPSyntaxes) OID() string { return `1.3.6.1.4.1.1466.101.120.16` }

/*
LDAPSyntax implements [§ 4.1.5 of RFC 4512].

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
type LDAPSyntax struct {
	NumericOID  string // IDENTIFIER
	Description string
	Extensions  map[int]Extension
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntax) String() (def string) {
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
func (r LDAPSyntax) Identifier() string {
	return r.NumericOID
}

/*
xPattern returns the regular expression statement assigned to the receiver.
This will be used by [LDAPSyntax.Verify] method to validate a
value against a custom syntax.
*/
func (r LDAPSyntax) xPattern() (xpat string) {
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
func (r LDAPSyntax) XOrigin() (origins []string) {
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
func (r LDAPSyntax) Match(term string) bool {
	return term == r.NumericOID || streqf(removeWHSP(term), removeWHSP(r.Description))
}

/*
HR returns a Boolean value indicative of whether the receiver instance
represents a human readable syntax.

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-NOT-HUMAN-READABLE` XString and a BOOLEAN ASN.1
value of `TRUE`.
*/
func (r LDAPSyntax) HR() (hr bool) {
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

Not to be confused with [LDAPSyntax.Valid] which only checks the validity
of a syntax definition itself -- not an assertion value.
*/
func (r LDAPSyntax) Verify(x any) (result Boolean) {
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
func (r LDAPSyntax) Valid() bool {
	_, err := marshalNumericOID(r.NumericOID)
	return err == nil
}

/*
MatchingRules implements [§ 4.2.3 of RFC 4512] and contains slices of
[MatchingRule].

[§ 4.2.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.3
*/
type MatchingRules []MatchingRule

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
Get returns an instance of [MatchingRule] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [MatchingRule]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRules) Get(term string) (def MatchingRule, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
MatchingRuleIndex returns the Nth [MatchingRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) MatchingRuleByIndex(idx int) (def MatchingRule) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.MatchingRules.Len() {
		def = r.MatchingRules[idx]
	}

	return
}

/*
MatchingRuleUseIndex returns the Nth [MatchingRuleUse] instances
found within the receiver instance.
*/
func (r *SubschemaSubentry) MatchingRuleUseByIndex(idx int) (def MatchingRuleUse) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.MatchingRuleUses.Len() {
		def = r.MatchingRuleUses[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.4" per [§ 4.2.3 of RFC 4512].

[§ 4.2.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.3
*/
func (r MatchingRules) OID() string { return `2.5.21.4` }

/*
MatchingRule implements [§ 4.1.3 of RFC 4512].

[§ 4.1.3 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3
*/
type MatchingRule struct {
	NumericOID  string
	Name        []string
	Description string
	Obsolete    bool
	Syntax      string
	Extensions  map[int]Extension
}

/*
EqualityMatch returns a [Boolean] instance alongside an error following an
attempt to perform an equality match between the actual and assertion input
values.

The actual value represents the value that would ostensibly be derived from
an LDAP DIT entry, while the assertion value represents the test value that
would be input by a requesting user.
*/
func (r MatchingRule) EqualityMatch(actual, assertion any) (result Boolean, err error) {
	if r.isEqualityRule() {
		result, err = r.executeAssertion(actual, assertion)
	} else {
		err = invalidMR
	}

	return
}

/*
SubstringsMatch returns a [Boolean] instance alongside an error following an
attempt to perform a substrings match between the actual and assertion input
values.

The actual value represents the value that would ostensibly be derived from
an LDAP DIT entry, while the assertion value represents the test value that
would be input by a requesting user.
*/
func (r MatchingRule) SubstringsMatch(actual, assertion any) (result Boolean, err error) {
	if r.isSubstringRule() {
		result, err = r.executeAssertion(actual, assertion)
	} else {
		err = invalidMR
	}

	return
}

/*
OrderingMatch returns a [Boolean] instance alongside an error following an
attempt to compare lo and hi in terms of ordering.

Comparison behavior is dictated through use the operator input byte value.
See the [GreaterOrEqual] and [LessOrEqual] constants for details.

The actual value represents the value that would ostensibly be derived from
an LDAP DIT entry, while the assertion value represents the test value that
would be input by a requesting user.
*/
func (r MatchingRule) OrderingMatch(actual, assertion any, operator byte) (result Boolean, err error) {
	if r.isOrderingRule() {
		result, err = r.executeAssertion(actual, assertion, operator)
	} else {
		err = invalidMR
	}

	return
}

/*
executeAssertion is the private handler method for EQUALITY, SUBSTR and
ORDERING matching rule operations.
*/
func (r MatchingRule) executeAssertion(actual, assertion any, operator ...byte) (result Boolean, err error) {
	if funk, found := matchingRuleAssertions[r.NumericOID]; found {
		switch funk.kind() {
		case `EQUALITY`:
			result, err = funk.(EqualityRuleAssertion)(actual, assertion)
		case `SUBSTR`:
			result, err = funk.(SubstringsRuleAssertion)(actual, assertion)
		case `ORDERING`:
			if len(operator) == 1 {
				result, err = funk.(OrderingRuleAssertion)(actual, assertion, operator[0])
			} else {
				err = invalidMR
			}
		default:
			err = invalidMR
		}
	} else {
		err = invalidMR
	}

	return
}

func (r MatchingRule) isSubstringRule() (is bool) {
	if len(r.Name) > 0 {
		is = cntns(lc(r.Name[0]), `substring`)
	}

	return
}

func (r MatchingRule) isOrderingRule() (is bool) {
	if len(r.Name) > 0 {
		is = cntns(lc(r.Name[0]), `ordering`)
	}

	return
}

func (r MatchingRule) isEqualityRule() (is bool) {
	return !r.isOrderingRule() && !r.isSubstringRule()
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition
originates.

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r MatchingRule) XOrigin() (origins []string) {
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
func (r MatchingRule) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRule) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r MatchingRule) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
newMatchingRuleUse initializes and returns a new instance of [MatchingRuleUse].
*/
func (r MatchingRule) newMatchingRuleUse() (mru MatchingRuleUse) {
	mru.NumericOID = r.NumericOID
	mru.Description = r.Description
	mru.Extensions = r.Extensions

	return
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver instance.
Note this does not verify the presence of dependency schema elements.
*/
func (r MatchingRule) Valid() bool {
	_, oerr := marshalNumericOID(r.NumericOID)
	_, serr := marshalNumericOID(r.Syntax)
	return oerr == nil && serr == nil
}

/*
AttributeTypes implements [§ 4.2.2 of RFC 4512] and contains slices of
[AttributeType].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
*/
type AttributeTypes []AttributeType

/*
OID returns the numeric OID literal "2.5.21.5" per [§ 4.2.2 of RFC 4512].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
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
Get returns an instance of [AttributeType] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [AttributeType]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r AttributeTypes) Get(term string) (def AttributeType, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
AttributeTypeIndex returns the Nth [AttributeType] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) AttributeTypeByIndex(idx int) (def AttributeType) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.AttributeTypes.Len() {
		def = r.AttributeTypes[idx]
	}

	return
}

/*
AttributeType implements [§ 4.1.2 of RFC 4512] and [§ 13.4.8 of ITU-T Rec. X.501] (AttributeType).

[§ 4.1.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2
[§ 13.4.8 of ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.520
*/
type AttributeType struct {
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
func (r AttributeType) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r AttributeType) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
SuperChain returns an instance of [AttributeTypes], which will
contain zero (0) or more slices of [AttributeType], each of which
representing an ascending superior type of the receiver instance.

The input classes instance should represent the [AttributeTypes]
instance obtained through a [SubschemaSubentry] instance.
*/
func (r AttributeType) SuperChain(types AttributeTypes) (supers AttributeTypes) {
	if &r != nil {
		supers = r.superChain(types)
	}

	return
}

func (r AttributeType) superChain(types AttributeTypes) (supers AttributeTypes) {
	if len(r.SuperType) != 0 {
		supers = make(AttributeTypes, 0)
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
func (r AttributeType) XOrigin() (origins []string) {
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
func (r AttributeType) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

func (r AttributeType) mutexBooleanString() (clause string) {
	if r.Single {
		clause += ` SINGLE-VALUE`
	} else if r.Collective {
		clause += ` COLLECTIVE`
	}

	return
}

func (r AttributeType) syntaxMatchingRuleClauses() (clause string) {
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
func (r AttributeType) Valid() bool {
	_, oerr := marshalNumericOID(r.NumericOID)
	result := oID(r.SuperType)

	_, xerr := marshalNumericOID(r.Syntax)

	return oerr == nil &&
		(result.True() || xerr == nil) &&
		!(r.Collective && r.Single)
}

/*
MatchingRuleUses implements [§ 4.2.4 of RFC 4512] and contains slices of
[MatchingRuleUse].

[§ 4.2.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.4
*/
type MatchingRuleUses []MatchingRuleUse

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUses) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		if def := r[i].String(); def != "" {
			s += r.Type() + `: ` + r[i].String() + string(rune(10))
		}
	}

	return
}

/*
Get returns an instance of [MatchingRuleUse] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [MatchingRuleUse]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRuleUses) Get(term string) (def MatchingRuleUse, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.8" per [§ 4.2.4 of RFC 4512].

[§ 4.2.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.4
*/
func (r MatchingRuleUses) OID() string { return `2.5.21.8` }

/*
MatchingRuleUse implements [§ 4.1.4 of RFC 4512].

[§ 4.1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.4
*/
type MatchingRuleUse struct {
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
func (r MatchingRuleUse) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r MatchingRuleUse) Identifier() (id string) {
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
func (r MatchingRuleUse) XOrigin() (origins []string) {
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
func (r MatchingRuleUse) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r MatchingRuleUse) Valid() bool {
	_, err := marshalNumericOID(r.NumericOID)

	/*
		// TODO: Not sure if we can do this in
		// this manner ...
		var bogusNumber int
		if len(r.Applies) == 0 {
			bogusNumber++
		}

		for _, at := range r.Applies {
			if !oID(at).True() {
				bogusNumber++
			}
		}
	*/

	return err == nil //&& bogusNumber == 0
}

/*
ObjectClasses implements [§ 4.2.1 of RFC 4512] and contains slices of
[ObjectClass].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
type ObjectClasses []ObjectClass

/*
OID returns the numeric OID literal "2.5.21.6" per [§ 4.2.1 of RFC 4512].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
func (r ObjectClasses) OID() string { return `2.5.21.6` }

/*
ObjectClassIndex returns the Nth [ObjectClass] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) ObjectClassByIndex(idx int) (def ObjectClass) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.ObjectClasses.Len() {
		def = r.ObjectClasses[idx]
	}

	return
}

/*
ObjectClass returns an instance of [ObjectClass] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [ObjectClass] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) ObjectClass(id string) (ObjectClass, int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.ObjectClasses.Get(id)
}

/*
SubordinateClasses returns slices of [ObjectClass], each of which are direct
subordinate classes of the input string id.

The input string id must be the numeric OID or name of the supposed superior
class.

Note that if a name is used, case-folding is not significant in the matching
process.

If zero slices are returned, this can mean either the superior class was not
found, or that it has no subordinate classes of its own.
*/
func (r SubschemaSubentry) SubordinateClasses(id string) (sub ObjectClasses) {
	if class, idx := r.ObjectClasses.Get(id); idx != -1 {
		for i := 0; i < r.ObjectClasses.Len(); i++ {
			oc := r.ObjectClasses[i]
			if strInSlice(class.NumericOID, oc.SuperClasses) {
				sub.Push(oc)
			} else {
				for n := 0; n < len(class.Name); n++ {
					if strInSlice(class.Name[n], oc.SuperClasses) {
						sub.Push(oc)
					}
				}
			}
		}
	}

	return
}

/*
SuperiorClasses returns slices of [ObjectClass], each of which are direct
superior object classes of the input string id.

The input string id must be the numeric OID or name of the subordinate
object class.

Note that if a name is used, case-folding is not significant in the
matching process.

If zero slices are returned, this can mean either the object class was
not found, or that it has no superior classes of its own.
*/
func (r SubschemaSubentry) SuperiorClasses(id string) (sup ObjectClasses) {
	if class, idx := r.ObjectClass(id); idx != -1 {
		for i := 0; i < len(class.SuperClasses); i++ {
			s := class.SuperClasses[i]
			if oc, sidx := r.ObjectClass(s); sidx != -1 {
				sup.Push(oc)
			}
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
Get returns an instance of [ObjectClass] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [ObjectClass]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r ObjectClasses) Get(term string) (def ObjectClass, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
ObjectClass implements [§ 4.1.1 of RFC 4512].

[§ 4.1.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1
*/
type ObjectClass struct {
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
func (r ObjectClass) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r ObjectClass) Identifier() (id string) {
	if len(r.Name) > 0 {
		id = r.Name[0]
	} else {
		id = r.NumericOID
	}

	return
}

/*
SuperChain returns an instance of [ObjectClasses], which will
contain zero (0) or more slices of [ObjectClass], each of which
representing a direct superior class of the receiver instance.

The input classes instance should represent the [ObjectClasses]
instance obtained through a [SubschemaSubentry] instance.
*/
func (r ObjectClass) SuperChain(classes ObjectClasses) (supers ObjectClasses) {
	for _, class := range r.SuperClasses {
		if def, idx := classes.Get(class); idx != -1 {
			supers = append(supers, def)
		}
	}
	supers = append(supers, r)

	return
}

/*
XOrigin returns slices of standards citations, each being the name of an RFC,
Internet-Draft or ITU-T Recommendation from which the receiver definition

This method is merely a convenient alternative to manually checking the
underlying Extensions field instance for the presence of an [Extension]
instance bearing the `X-ORIGIN` XString and at least one (1) value.
*/
func (r ObjectClass) XOrigin() (origins []string) {
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
func (r ObjectClass) Match(term string) bool {
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

func definitionMVDescriptors(key string, src any, dsr ...bool) (clause string) {
	var isDsr bool
	if len(dsr) > 0 {
		isDsr = dsr[0]
	}
	switch tv := src.(type) {
	case string:
		if len(tv) > 0 {
			clause += ` ` + uc(key) + ` ` + tv
		}
	case []string:
		if len(tv) > 0 {
			delim := ` $ `
			if isDsr {
				delim = ` `
			}
			clause += ` ` + uc(key) + ` ` + stringDescrs(tv, delim)
		}
	}

	return
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r ObjectClass) Valid() bool {
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
AllMust returns an [AttributeTypes] instance containing zero (0)
or more MANDATORY [AttributeType] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered [AttributeType]
slice instances known to be registered within the relevant [SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
[ObjectClass] instances known to be registered within that same
[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClass) AllMust(types AttributeTypes,
	classes ObjectClasses) (must AttributeTypes) {
	must = make(AttributeTypes, 0)

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
AllMay returns an [AttributeTypes] instance containing zero (0)
or more OPTIONAL [AttributeType] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered [AttributeType]
slice instances known to be registered within the relevant [SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
[ObjectClass] instances known to be registered within that same
[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClass) AllMay(types AttributeTypes,
	classes ObjectClasses) (may AttributeTypes) {
	may = make(AttributeTypes, 0)

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
DITContentRules implements [§ 4.2.6 of RFC 4512] and contains slices of
[DITContentRule].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
type DITContentRules []DITContentRule

/*
OID returns the numeric OID literal "2.5.21.2" per [§ 4.2.6 of RFC 4512].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
func (r DITContentRules) OID() string { return `2.5.21.2` }

/*
DITContentRuleIndex returns the Nth [DITContentRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) DITContentRuleByIndex(idx int) (def DITContentRule) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.DITContentRules.Len() {
		def = r.DITContentRules[idx]
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
Get returns an instance of [DITContentRule] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [DITContentRule]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITContentRules) Get(term string) (def DITContentRule, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
DITContentRule implements [§ 4.1.6 of RFC 4512].

[§ 4.1.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6
*/
type DITContentRule struct {
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
func (r DITContentRule) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r DITContentRule) Identifier() (id string) {
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
func (r DITContentRule) XOrigin() (origins []string) {
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
func (r DITContentRule) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r DITContentRule) Valid() bool {
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
NameForms implements [§ 4.2.8 of RFC 4512] and contains slices of
[NameForm].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
type NameForms []NameForm

/*
OID returns the numeric OID literal "2.5.21.7" per [§ 4.2.8 of RFC 4512].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
func (r NameForms) OID() string { return `2.5.21.7` }

/*
NameFormIndex returns the Nth [NameForm] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) NameFormByIndex(idx int) (def NameForm) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.NameForms.Len() {
		def = r.NameForms[idx]
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
Get returns an instance of [NameForm] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of [NameForm]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r NameForms) Get(term string) (def NameForm, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
NameForm implements [§ 4.1.7.2 of RFC 4512].

[§ 4.1.7.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2
*/
type NameForm struct {
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
func (r NameForm) String() (def string) {
	if r.Valid() {
		def = `( ` + r.NumericOID
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
func (r NameForm) Identifier() (id string) {
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
func (r NameForm) XOrigin() (origins []string) {
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
func (r NameForm) Match(term string) bool {
	return term == r.NumericOID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r NameForm) Valid() bool {
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
DITStructureRules implements [§ 4.2.7 of RFC 4512] and contains slices of
[DITStructureRule].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
type DITStructureRules []DITStructureRule

/*
OID returns the numeric OID literal "2.5.21.1" per [§ 4.2.7 of RFC 4512].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
func (r DITStructureRules) OID() string { return `2.5.21.1` }

/*
DITStructureRuleIndex returns the Nth [DITStructureRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) DITStructureRuleByIndex(idx int) (def DITStructureRule) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if 0 <= idx && idx < r.DITStructureRules.Len() {
		def = r.DITStructureRules[idx]
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
Get returns an instance of [DITStructureRule] and a slice index following
a descriptor or integer identifier match attempt. A zero instance of [DITStructureRule]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITStructureRules) Get(term string) (def DITStructureRule, idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r[i].Match(term) {
			def = r[i]
			idx = i
		}
	}

	return
}

/*
DITStructureRule implements [§ 4.1.7.1 of RFC 4512].

[§ 4.1.7.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1
*/
type DITStructureRule struct {
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
func (r DITStructureRule) String() (def string) {
	if r.Valid() {
		def = `( ` + r.RuleID
		def += definitionName(r.Name)
		def += definitionDescription(r.Description)
		def += stringBooleanClause(`OBSOLETE`, r.Obsolete)
		def += definitionMVDescriptors(`FORM`, r.Form)
		def += definitionMVDescriptors(`SUP`, r.SuperRules, true)
		def += stringExtensions(r.Extensions)
		def += ` )`
	}

	return
}

/*
Identifier returns the principal string value by which the receiver
is known. If the receiver is not assigned a name (descriptor), the
integer identifier (rule ID) is returned instead.
*/
func (r DITStructureRule) Identifier() (id string) {
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
func (r DITStructureRule) XOrigin() (origins []string) {
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
term value and the receiver's integer rule identifier (rule ID) or Name value.

Case is not significant in the matching process.
*/
func (r DITStructureRule) Match(term string) bool {
	return term == r.RuleID || strInSlice(term, r.Name)
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r DITStructureRule) Valid() bool {
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

func marshalExtension(token, typ string, tkz *schemaTokenizer) (ext Extension, err error) {
	if tpfx := uc(token); hasPfx(tpfx, "X-") {
		ext = Extension{
			XString: tpfx,
			Values:  parseMultiVal(tkz),
		}
	} else {
		err = errorTxt(typ + ": Unknown token in definition: " + token)
	}

	return
}

func lDAPSyntaxDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "LDAPSyntax"); err == nil {
		_, err = marshalLDAPSyntax(str)
		result.Set(err == nil)
	}
	return
}

func marshalLDAPSyntax(x any) (def LDAPSyntax, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	if tkz.next() && tkz.this() == `(` {
		tkz.next()
	}

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
		token := tkz.this()
		switch token {
		case ")":
			if tkz.isFinalToken() {
				return
			}
		case "DESC":
			def.Description = parseSingleVal(tkz)
		default:
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func matchingRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "MatchingRule"); err == nil {
		_, err := marshalMatchingRule(str)
		result.Set(err == nil)
	}
	return
}

func marshalMatchingRule(x any) (def MatchingRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func matchingRuleUseDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "MatchingRuleUse"); err == nil {
		_, err := marshalMatchingRuleUse(str)
		result.Set(err == nil)
	}
	return
}

func marshalMatchingRuleUse(x any) (def MatchingRuleUse, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func attributeTypeDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "AttributeType"); err == nil {
		_, err = marshalAttributeType(str)
		result.Set(err == nil)
	}
	return
}

func marshalAttributeType(x any) (def AttributeType, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func (r *AttributeType) handleBoolean(token string) (err error) {
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

func (r *AttributeType) handleSyntaxMatchingRules(token string, tkz *schemaTokenizer) (err error) {
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
	if str, err := assertString(x, 9, "ObjectClass"); err == nil {
		_, err = marshalObjectClass(str)
		result.Set(err == nil)
	}
	return
}

func assertObjectClass(x any) (def ObjectClass, err error) {
	switch tv := x.(type) {
	case ObjectClass:
		def = tv
	default:
		def, err = marshalObjectClass(tv)
	}

	return
}

func marshalObjectClass(x any) (def ObjectClass, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func parseClassKind(token string) (kind uint8) {
	switch token {
	case `STRUCTURAL`:
	case `AUXILIARY`:
		kind = uint8(1)
	case `ABSTRACT`:
		kind = uint8(2)
	}
	return
}

func dITContentRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "DITContentRule"); err == nil {
		_, err = marshalDITContentRule(str)
		result.Set(err == nil)
	}
	return
}

func assertDITContentRule(x any) (def DITContentRule, err error) {
	switch tv := x.(type) {
	case DITContentRule:
		def = tv
	default:
		def, err = marshalDITContentRule(tv)
	}

	return
}

func marshalDITContentRule(x any) (def DITContentRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func nameFormDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "NameForm"); err == nil {
		_, err = marshalNameForm(str)
		result.Set(err == nil)
	}
	return
}

func marshalNameForm(x any) (def NameForm, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.NumericOID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func dITStructureRuleDescription(x any) (result Boolean) {
	if str, err := assertString(x, 9, "DITStructureRule"); err == nil {
		_, err = marshalDITStructureRule(str)
		result.Set(err == nil)
	}
	return
}

func assertDITStructureRule(x any) (def DITStructureRule, err error) {
	switch tv := x.(type) {
	case DITStructureRule:
		def = tv
	default:
		def, err = marshalDITStructureRule(tv)
	}

	return
}

func marshalDITStructureRule(x any) (def DITStructureRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType(def.Type())
		return
	}

	def.Extensions = make(map[int]Extension)

	input = trimS(trimDefinitionLabelToken(input))
	tkz := newSchemaTokenizer(input)
	tkz.startTokenParen()

	def.RuleID = tkz.this()

	for tkz.next() && err == nil {
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
			def.Extensions[len(def.Extensions)], err =
				marshalExtension(token, def.Type(), tkz)
		}
	}

	return
}

func (r *schemaTokenizer) startTokenParen() {
	if r.next() && r.this() == "(" {
		r.next()
	}
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
		clause = ` ` + token
	}

	return
}

func trimDefinitionLabelToken(input string) string {
	low := lc(input)
	for _, token := range headerTokens {
		if hasPfx(low, lc(token)) {
			rest := input[len(token):]

			// Skip optional colon or space
			rest = trimS(trimL(rest, ":"))

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
func (r LDAPSyntax) OID() string { return `1.3.6.1.4.1.1466.115.121.1.54` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.30" per
[§ 3.3.19 of RFC 4517].

[§ 3.3.19 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.19
*/
func (r MatchingRule) OID() string { return `1.3.6.1.4.1.1466.115.121.1.30` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.3" per
[§ 3.3.1 of RFC 4517].

[§ 3.3.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.1
*/
func (r AttributeType) OID() string { return `1.3.6.1.4.1.1466.115.121.1.3` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.31" per
[§ 3.3.20 of RFC 4517].

[§ 3.3.20 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.20
*/
func (r MatchingRuleUse) OID() string { return `1.3.6.1.4.1.1466.115.121.1.31` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.37" per
[§ 3.3.24 of RFC 4517].

[§ 3.3.24 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.24
*/
func (r ObjectClass) OID() string { return `1.3.6.1.4.1.1466.115.121.1.37` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.16" per
[§ 3.3.7 of RFC 4517].

[§ 3.3.7 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.7
*/
func (r DITContentRule) OID() string { return `1.3.6.1.4.1.1466.115.121.1.16` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.35" per
[§ 3.3.22 of RFC 4517].

[§ 3.3.22 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.22
*/
func (r NameForm) OID() string { return `1.3.6.1.4.1.1466.115.121.1.35` }

/*
OID returns the numeric OID literal "1.3.6.1.4.1.1466.115.121.1.17" per
[§ 3.3.8 of RFC 4517].

[§ 3.3.8 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.8
*/
func (r DITStructureRule) OID() string { return `1.3.6.1.4.1.1466.115.121.1.17` }

func (r LDAPSyntaxes) Len() int      { return len(r) }
func (r MatchingRules) Len() int     { return len(r) }
func (r AttributeTypes) Len() int    { return len(r) }
func (r MatchingRuleUses) Len() int  { return len(r) }
func (r ObjectClasses) Len() int     { return len(r) }
func (r DITContentRules) Len() int   { return len(r) }
func (r NameForms) Len() int         { return len(r) }
func (r DITStructureRules) Len() int { return len(r) }

func (r LDAPSyntaxes) Type() string      { return headerTokens[0] }
func (r MatchingRules) Type() string     { return headerTokens[2] }
func (r AttributeTypes) Type() string    { return headerTokens[4] }
func (r MatchingRuleUses) Type() string  { return headerTokens[6] }
func (r ObjectClasses) Type() string     { return headerTokens[8] }
func (r DITContentRules) Type() string   { return headerTokens[10] }
func (r NameForms) Type() string         { return headerTokens[12] }
func (r DITStructureRules) Type() string { return headerTokens[14] }

func (r LDAPSyntax) Type() string       { return headerTokens[1] }
func (r MatchingRule) Type() string     { return headerTokens[3] }
func (r AttributeType) Type() string    { return headerTokens[5] }
func (r MatchingRuleUse) Type() string  { return headerTokens[7] }
func (r ObjectClass) Type() string      { return headerTokens[9] }
func (r DITContentRule) Type() string   { return headerTokens[11] }
func (r NameForm) Type() string         { return headerTokens[13] }
func (r DITStructureRule) Type() string { return headerTokens[15] }

func (r LDAPSyntax) isDefinition()       {}
func (r MatchingRule) isDefinition()     {}
func (r AttributeType) isDefinition()    {}
func (r MatchingRuleUse) isDefinition()  {}
func (r ObjectClass) isDefinition()      {}
func (r DITContentRule) isDefinition()   {}
func (r NameForm) isDefinition()         {}
func (r DITStructureRule) isDefinition() {}

func (r LDAPSyntaxes) isDefinitions()      {}
func (r MatchingRules) isDefinitions()     {}
func (r AttributeTypes) isDefinitions()    {}
func (r MatchingRuleUses) isDefinitions()  {}
func (r ObjectClasses) isDefinitions()     {}
func (r DITContentRules) isDefinitions()   {}
func (r NameForms) isDefinitions()         {}
func (r DITStructureRules) isDefinitions() {}

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
