package dirsyn

/*
schema.go implements much of Section 4 of RFC 4512.
*/

import (
	_ "embed"
	"io/fs"
	"path/filepath"
	"sync"
)

//go:embed ls.schema
var lsPrimer []byte

//go:embed mr.schema
var mrPrimer []byte

var invalidSchema *SubschemaSubentry = &SubschemaSubentry{
	LDAPSyntaxes:      &LDAPSyntaxes{},
	MatchingRules:     &MatchingRules{},
	AttributeTypes:    &AttributeTypes{},
	MatchingRuleUses:  &MatchingRuleUses{},
	ObjectClasses:     &ObjectClasses{},
	DITContentRules:   &DITContentRules{},
	NameForms:         &NameForms{},
	DITStructureRules: &DITStructureRules{},
}

/*
SubschemaSubentry returns a freshly initialized instance of *[SubschemaSubentry].
Instances of this type serve as a platform upon which individual text definitions
may be parsed into usable instances of [SchemaDefinition].

The prime variadic argument controls whether to prime, or "pre-load", standard
[LDAPSyntax] and [MatchingRule] definitions sourced from RFC 4512, RFC 4523 and
RFC 2307 into the receiver instance. The default is false, which results in no
such definitions being pre-loaded.

Generally speaking, it is RECOMMENDED that users pre-load these definitions UNLESS
they are constructing a very stringent schema structure which only contains select
syntaxes and matching rules -- a most unusual circumstance. In such a case, users
will be required to register those select syntaxes and matching rules MANUALLY.
*/
func (r RFC4512) SubschemaSubentry(prime ...bool) (sch *SubschemaSubentry, err error) {
	sch = &SubschemaSubentry{
		LDAPSyntaxes:      &LDAPSyntaxes{mutex: &sync.Mutex{}},
		MatchingRules:     &MatchingRules{mutex: &sync.Mutex{}},
		AttributeTypes:    &AttributeTypes{mutex: &sync.Mutex{}},
		MatchingRuleUses:  &MatchingRuleUses{mutex: &sync.Mutex{}},
		ObjectClasses:     &ObjectClasses{mutex: &sync.Mutex{}},
		DITContentRules:   &DITContentRules{mutex: &sync.Mutex{}},
		NameForms:         &NameForms{mutex: &sync.Mutex{}},
		DITStructureRules: &DITStructureRules{mutex: &sync.Mutex{}},
	}

	if len(prime) > 0 {
		if prime[0] {
			err = sch.primeBuiltIns()
		}
	}

	// Set internal *SubschemaSubentry reference.
	sch.LDAPSyntaxes.setSchema(sch)
	sch.MatchingRules.setSchema(sch)
	sch.AttributeTypes.setSchema(sch)
	sch.MatchingRuleUses.setSchema(sch)
	sch.ObjectClasses.setSchema(sch)
	sch.DITContentRules.setSchema(sch)
	sch.NameForms.setSchema(sch)
	sch.DITStructureRules.setSchema(sch)

	return
}

/*
NewLDAPSyntaxes returns an empty, but initialized and thread-safe, instance of
*[LDAPSyntaxes] intended for general use.
*/
func (r *SubschemaSubentry) NewLDAPSyntaxes() *LDAPSyntaxes {
	x := &LDAPSyntaxes{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewMatchingRules returns an empty, but initialized and thread-safe, instance of
*[MatchingRules] intended for general use.
*/
func (r *SubschemaSubentry) NewMatchingRules() *MatchingRules {
	x := &MatchingRules{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewAttributeTypes returns an empty, but initialized and thread-safe, instance of
*[AttributeTypes] intended for general use.
*/
func (r *SubschemaSubentry) NewAttributeTypes() *AttributeTypes {
	x := &AttributeTypes{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewMatchingRuleUses returns an empty, but initialized and thread-safe, instance of
*[MatchingRuleUses] intended for general use.
*/
func (r *SubschemaSubentry) NewMatchingRuleUses() *MatchingRuleUses {
	x := &MatchingRuleUses{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewObjectClasses returns an empty, but initialized and thread-safe, instance of
*[ObjectClasses] intended for general use.
*/
func (r *SubschemaSubentry) NewObjectClasses() *ObjectClasses {
	x := &ObjectClasses{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewDITContentRules returns an empty, but initialized and thread-safe, instance of
*[DITContentRules] intended for general use.
*/
func (r *SubschemaSubentry) NewDITContentRules() *DITContentRules {
	x := &DITContentRules{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewNameForms returns an empty, but initialized and thread-safe, instance of
*[NameForms] intended for general use.
*/
func (r *SubschemaSubentry) NewNameForms() *NameForms {
	x := &NameForms{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
}

/*
NewDITStructureRules returns an empty, but initialized and thread-safe, instance of
*[DITStructureRules] intended for general use.
*/
func (r *SubschemaSubentry) NewDITStructureRules() *DITStructureRules {
	x := &DITStructureRules{
		schema: invalidSchema,
	}

	if r != nil {
		x.mutex = &sync.Mutex{}
		x.schema = r
	}

	return x
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
	if _, err = ostat(dir); !erris(err, errNotExist) {
		// recurse dir path
		err = filepath.Walk(dir, func(p string, d fs.FileInfo, err error) error {
			if !d.IsDir() && hasSfx(d.Name(), ".schema") {
				err = r.ReadFile(p)
			}

			return err
		})
	}

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
	for i := 0; i < len(defs); i++ {
		def := defs[i]
		switch tv := def.(type) {
		case *LDAPSyntax:
			r.LDAPSyntaxes.Push(tv)
		case *MatchingRule:
			r.MatchingRules.Push(tv)
		case *AttributeType:
			r.AttributeTypes.Push(tv)
		case *MatchingRuleUse:
			if internal {
				r.MatchingRuleUses.push(tv)
			}
		case *ObjectClass:
			r.ObjectClasses.Push(tv)
		case *DITContentRule:
			r.DITContentRules.Push(tv)
		case *NameForm:
			r.NameForms.Push(tv)
		case *DITStructureRule:
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
		case *LDAPSyntax:
			err = r.UnregisterLDAPSyntax(tv)
		case *MatchingRule:
			err = r.UnregisterMatchingRule(tv)
		case *AttributeType:
			err = r.UnregisterAttributeType(tv)
		case *ObjectClass:
			err = r.UnregisterObjectClass(tv)
		case *DITContentRule:
			err = r.UnregisterDITContentRule(tv)
		case *NameForm:
			err = r.UnregisterNameForm(tv)
		case *DITStructureRule:
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
EffectiveEquality returns an instance of (EQUALITY) *[MatchingRule] which reflects
the effective matchingRule honored by the receiver instance, whether direct or by
way of a super type in the super chain.

If the receiver instance both possesses its own [MatchingRule] AND is a subtype of
another (valid) [AttributeType] definition, the local [MatchingRule] has precedence
and is returned.
*/
func (r AttributeType) EffectiveEquality() (rule *MatchingRule) {
	if s := r.Equality; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.schema.MatchingRules.Get(s)
	} else if u := r.SuperType; len(u) > 0 {
		if sup, sidx := r.schema.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = sup.EffectiveEquality()
		}
	}

	return
}

/*
EffectiveSubstring returns an instance of (SUBSTR) *[MatchingRule] which reflects
the effective matchingRule honored by the receiver instance, whether direct or by
way of a super type in the super chain.

If the receiver instance both possesses its own [MatchingRule] AND is a subtype of
another (valid) [AttributeType] definition, the local [MatchingRule] has precedence
and is returned.
*/
func (r AttributeType) EffectiveSubstring() (rule *MatchingRule) {
	if s := r.Substring; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.schema.MatchingRules.Get(s)
	} else if u := r.SuperType; len(u) > 0 {
		if sup, sidx := r.schema.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = sup.EffectiveSubstring()
		}
	}

	return
}

/*
EffectiveOrdering returns an instance of (ORDERING) *[MatchingRule] which reflects
the effective matchingRule honored by the receiver instance, whether direct or by
way of a super type in the super chain.

If the receiver instance both possesses its own [MatchingRule] AND is a subtype of
another (valid) [AttributeType] definition, the local [MatchingRule] has precedence
and is returned.
*/
func (r AttributeType) EffectiveOrdering() (rule *MatchingRule) {
	if s := r.Ordering; len(s) > 0 {
		// matchingRule is honored locally, so use it.
		rule, _ = r.schema.MatchingRules.Get(s)
	} else if u := r.SuperType; len(u) > 0 {
		if sup, sidx := r.schema.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			rule = sup.EffectiveOrdering()
		}
	}

	return
}

/*
EffectiveSyntax returns an instance of *[LDAPSyntax] which reflects the effective
syntax honored by receiver instance, whether direct or by way of a super type in
the super chain.

The return instance of *[LDAPSyntax] should NEVER be zero, as all [AttributeType]
instances are expected to honor a syntax in some way.

If the receiver instance both possesses its own [LDAPSyntax] AND is a subtype of
another (valid) *[AttributeType] definition, the local [LDAPSyntax] has precedence
and is returned.
*/
func (r AttributeType) EffectiveSyntax() (syntax *LDAPSyntax) {
	if s := r.Syntax; len(s) > 0 {
		// Syntax is honored locally, so use it.
		syntax, _ = r.schema.LDAPSyntaxes.Get(s)
	} else if u := r.SuperType; len(u) > 0 {
		if sup, sidx := r.schema.AttributeTypes.Get(u); sidx != -1 {
			// Recurse to the super type.
			syntax = sup.EffectiveSyntax()
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

	// Table returns an instance of [SchemaDefinitionTable].
	Table() SchemaDefinitionTable

	// setSchema is a private method which assigns the input
	// instance of SubschemaSubentry to the receiver instance.
	setSchema(*SubschemaSubentry)

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
	*LDAPSyntaxes
	*MatchingRules
	*AttributeTypes
	*MatchingRuleUses
	*ObjectClasses
	*DITContentRules
	*NameForms
	*DITStructureRules
}

/*
SchemaDefinitionTable implements a basic map[string][]string lookup table for a
particular [SchemaDefinitions] instance.

With the exception of [DITStructureRules], which uses integer identifiers (e.g.: "1"), the
keys are numeric OIDs (e.g.: "2.5.4.3").

With the exception of [LDAPSyntaxes], which uses a description string, the values are zero
(0) or more string slices, each representing a descriptor (name) by which the definition is
known (e.g.: []string{"cn","commonName"})

Instances of this type may be created using any of the following methods:

  - [LDAPSyntaxes.Table]
  - [MatchingRules.Table]
  - [AttributeTypes.Table]
  - [MatchingRuleUses.Table]
  - [ObjectClasses.Table]
  - [DITContentRules.Table]
  - [NameForms.Table]
  - [DITStructureRules.Table]
*/
type SchemaDefinitionTable map[string][]string

/*
primeBuiltIns is a private method used to pre-load standard LDAPSyntax
and MatchingRule instances sourced from formalized RFCs.
*/
func (r *SubschemaSubentry) primeBuiltIns() (err error) {

	if err = r.ReadBytes(lsPrimer); err == nil {
		err = r.ReadBytes(mrPrimer)
	}

	return
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

func assertLDAPSyntax(x any) (def *LDAPSyntax, err error) {
	switch tv := x.(type) {
	case LDAPSyntax:
		def = &tv
	case *LDAPSyntax:
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
	var def *LDAPSyntax
	if def, err = assertLDAPSyntax(input); err != nil {
		return
	}
	def.schema = r

	if _, idx := r.LDAPSyntax(def.NumericOID); idx != -1 {
		err = errorTxt("ldapSyntax: Duplicate registration: '" + def.NumericOID + "'")
		return
	}

	r.Push(def)

	return
}

func (r *SubschemaSubentry) ldapSyntaxDepScan(def *LDAPSyntax) (err error) {
	var mr, at int
	for i := 0; i < r.MatchingRules.Len(); i++ {
		if cand := r.MatchingRules.Index(i); cand.Syntax == def.NumericOID {
			mr++
		}
	}

	for i := 0; i < r.AttributeTypes.Len(); i++ {
		if cand := r.AttributeTypes.Index(i); cand.Syntax == def.NumericOID {
			at++
		}
	}

	if mr > 0 || at > 0 {
		err = errorTxt(def.Type() + " has dependents: " + itoa(mr) +
			" matchingRule, " + itoa(at) + " attributeType")
	}

	return
}

/*
UnregisterLDAPSyntax returns an error following an attempt to remove the
specified definition from the receiver instance. A successful run will also
remove the associated [MatchingRuleUse] instance.

Valid input types may be an instance of *[LDAPSyntax], or its equivalent string
representation (LDAPSyntaxDescription) as described in [§ 4.1.5 of RFC 4512].

Note that this process shall fail if the specified definition has dependent
matchingRule or attributeType definitions.

[§ 4.1.5 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5
*/
func (r *SubschemaSubentry) UnregisterLDAPSyntax(input any) (err error) {
	var def *LDAPSyntax
	if def, err = assertLDAPSyntax(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.LDAPSyntaxes.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	err = r.LDAPSyntaxes.unregister(idx, def, r.ldapSyntaxDepScan)
	return
}

func assertMatchingRule(x any) (def *MatchingRule, err error) {
	switch tv := x.(type) {
	case MatchingRule:
		def = &tv
	case *MatchingRule:
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
	var def *MatchingRule
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

	// Initialize MRU using new MR def.
	mru := def.newMatchingRuleUse()
	mru.schema = r

	r.Push(def)
	r.push(true, mru)

	return
}

func (r *SubschemaSubentry) matchingRuleDepScan(def *MatchingRule) (err error) {
	// First check to see if an associated matchingRuleUse
	// instance exists AND still has users...
	var mu, at int

	mru, idx := r.MatchingRuleUses.Get(def.NumericOID)
	if idx != -1 && len(mru.Applies) > 0 {
		mu++
	}

	// Next check to see if the matchingRule instance
	// exists AND is used by any attributeType instances
	// for EQUALITY, ORDERING or SUBSTR.
	for i := 0; i < r.AttributeTypes.Len() && err == nil; i++ {
		for _, mrt := range []string{
			r.AttributeTypes.Index(i).Equality,
			r.AttributeTypes.Index(i).Ordering,
			r.AttributeTypes.Index(i).Substring,
		} {
			if def.Match(mrt) {
				at++
			}
		}
	}

	if mu > 0 || at > 0 {
		err = errorTxt(def.Type() + " has dependents: " + itoa(mu) +
			" matchingRuleUse, " + itoa(at) + " attributeType")
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
	var def *MatchingRule
	if def, err = assertMatchingRule(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.MatchingRules.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	err = r.MatchingRules.unregister(idx, def, r.matchingRuleDepScan)
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
	var def *AttributeType
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
			var rule *MatchingRule
			var idx int

			if rule, idx = r.MatchingRules.Get(mr); idx == -1 {
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
func (r AttributeType) SuperiorType() (sup *AttributeType) {
	if r.schema != nil {
		if typ, idx := r.schema.AttributeTypes.Get(r.Identifier()); idx != -1 {
			if typ.SuperType != "" {
				if at, sidx := r.schema.AttributeType(typ.SuperType); sidx != -1 {
					sup = at
				}
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
func (r AttributeType) SubordinateTypes() (sub *AttributeTypes) {
	sub = &AttributeTypes{}
	if r.schema != nil {
		sub = r.schema.NewAttributeTypes()
		for i := 0; i < r.schema.AttributeTypes.Len(); i++ {
			if at := r.schema.AttributeTypes.Index(i); !at.IsZero() {
				if strInSlice(at.SuperType, append([]string{r.NumericOID}, r.Name...)) {
					sub.Push(at)
				}
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeDepScan(def *AttributeType) (err error) {

	if r == nil || def == nil {
		err = nilInstanceErr
		return
	}

	if deps := def.SubordinateTypes(); deps.Len() > 0 {
		err = errorTxt("attributeType has subordinate attributeType dependents")
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

func (r *SubschemaSubentry) attributeTypeObjectClassDepScan(def *AttributeType) (err error) {
	for n := 0; n < r.ObjectClasses.Len(); n++ {
		for _, slice := range [][]string{
			r.ObjectClasses.Index(n).Must,
			r.ObjectClasses.Index(n).May,
		} {
			if strInSlice(append([]string{def.NumericOID}, def.Name...), slice) {
				err = errorTxt("attributeType has objectClass dependents")
				return
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeDITContentRuleDepScan(def *AttributeType) (err error) {
	for n := 0; n < r.DITContentRules.Len(); n++ {
		for _, slice := range [][]string{
			r.DITContentRules.Index(n).Must,
			r.DITContentRules.Index(n).May,
			r.DITContentRules.Index(n).Not,
		} {
			if strInSlice(append([]string{def.NumericOID}, def.Name...), slice) {
				err = errorTxt("attributeType has dITContentRule dependents")
				return
			}
		}
	}

	return
}

func (r *SubschemaSubentry) attributeTypeNameFormDepScan(def *AttributeType) (err error) {
	for n := 0; n < r.NameForms.Len(); n++ {
		for _, slice := range [][]string{
			r.NameForms.Index(n).Must,
			r.NameForms.Index(n).May,
		} {
			if strInSlice(append([]string{def.NumericOID}, def.Name...), slice) {
				err = errorTxt("attributeType has nameForm dependents")
				return
			}
		}
	}

	return
}

func assertAttributeType(x any) (def *AttributeType, err error) {
	switch tv := x.(type) {
	case AttributeType:
		def = &tv
	case *AttributeType:
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
	var def *AttributeType
	if def, err = assertAttributeType(input); err != nil {
		return
	}
	def.schema = r

	if _, idx := r.AttributeTypes.Get(def.NumericOID); idx == -1 {
		err = errorTxt(def.Type() + " not found")
	} else {
		err = r.AttributeTypes.unregister(idx, def, r.attributeTypeDepScan)
		r.unregisterMatchingRuleUsers(def)
	}

	return
}

func (r *SubschemaSubentry) unregisterMatchingRuleUsers(def *AttributeType) {
	for i := 0; i < r.MatchingRuleUses.Len(); i++ {
		r.MatchingRuleUses.Index(i).truncate(def)
	}
}

func (r *LDAPSyntaxes) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *LDAPSyntaxes) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *MatchingRules) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *MatchingRules) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *AttributeTypes) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *AttributeTypes) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *MatchingRuleUses) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *MatchingRuleUses) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *ObjectClasses) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *ObjectClasses) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *DITContentRules) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *DITContentRules) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *NameForms) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *NameForms) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

func (r *DITStructureRules) lock() {
	if r.mutex != nil {
		r.mutex.Lock()
	}
}

func (r *DITStructureRules) unlock() {
	if r.mutex != nil {
		r.mutex.Unlock()
	}
}

/*
truncate removes the Nth APPLIES slice.
*/
func (r *MatchingRuleUse) truncate(def *AttributeType) {
	for i := 0; i < len(r.Applies); i++ {
		if strInSlice(append([]string{def.NumericOID}, def.Name...), r.Applies) {
			r.Applies = append(r.Applies[:i], r.Applies[i+1:]...)
		}
	}
}

/*
truncate removes the Nth MatchingRuleUse instance.
*/
func (r *MatchingRuleUses) truncate(idx int) {
	r.lock()
	defer r.unlock()
	if 0 <= idx && idx <= r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
	}
}

func (r *SubschemaSubentry) updateMatchingRuleUse(def *AttributeType, mrups map[string]string) {
	// Update appropriate MRUs to include new attr OID
	for _, v := range mrups {
		if _, idx := r.MatchingRuleUses.Get(v); idx != -1 {
			if mru := r.MatchingRuleUses.Index(idx); !mru.IsZero() {
				if found := strInSlice(append([]string{def.NumericOID}, def.Name...), mru.Applies); !found {
					mru.Applies = append(mru.Applies, def.Identifier())
				}
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
	var def *ObjectClass
	if def, err = assertObjectClass(input); err != nil {
		return
	}

	if _, idx := r.ObjectClasses.Get(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeTypes.Get(at); idx == -1 {
				err = errorTxt("objectClass: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	// Make sure superclasses, if present, are sane.
	for i := 0; i < len(def.SuperClasses); i++ {
		if _, idx := r.ObjectClasses.Get(def.SuperClasses[i]); idx == -1 {
			err = errorTxt("objectClass: Unknown SUP (superclass): '" +
				def.SuperClasses[i] + "'")
			return
		}
	}

	r.Push(def)

	return
}

func (r *SubschemaSubentry) objectClassDepScan(def *ObjectClass) (err error) {
	if deps := def.SubordinateClasses(); deps.Len() > 0 {
		err = errorTxt(def.Type() + " has subordinate objectClass dependents")
	} else if def.Kind == 0 {
		// Scan for dependent nameForm or dITContentRule
		// instances IF the class is STRUCTURAL ...
		for n := 0; n < r.NameForms.Len(); n++ {
			nf := r.NameForms.Index(n)
			if strInSlice(nf.OC, append([]string{def.NumericOID}, def.Name...)) {
				err = errorTxt(def.Type() + " has nameForm dependents")
				return
			}
		}
		for d := 0; d < r.DITContentRules.Len(); d++ {
			dcr := r.DITContentRules.Index(d)
			if dcr.NumericOID == def.NumericOID {
				err = errorTxt(def.Type() + " has dITContentRule dependents")
				return
			}
		}
	} else if def.Kind == 1 {
		// Scan for dependent dITContentRule
		// instances IF the class is AUXILIARY
		for d := 0; d < r.DITContentRules.Len(); d++ {
			dcr := r.DITContentRules.Index(d)
			if strInSlice(append([]string{def.NumericOID}, def.Name...), dcr.Aux) {
				err = errorTxt(def.Type() + " has dITContentRule dependents")
				return
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
	var def *ObjectClass
	if def, err = assertObjectClass(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.ObjectClasses.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	err = r.ObjectClasses.unregister(idx, def, r.objectClassDepScan)
	return
}

func (r *SubschemaSubentry) dITContentRuleDepScan(def *DITContentRule) (err error) {
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
	var def *DITContentRule
	if def, err = assertDITContentRule(input); err != nil {
		return
	}

	if _, idx := r.ObjectClasses.Get(def.NumericOID); idx == -1 {
		err = errorTxt("dITContentRule: Unregistered structural class OID: '" +
			def.NumericOID + "'")
		return
	} else if _, idx := r.DITContentRules.Get(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeTypes.Get(at); idx == -1 {
				err = errorTxt("dITContentRule: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	// Make sure auxiliary classes, if present, are sane.
	for i := 0; i < len(def.Aux); i++ {
		if _, idx := r.ObjectClasses.Get(def.Aux[i]); idx == -1 {
			err = errorTxt("dITContentRule: Unknown AUX (auxiliary class): '" +
				def.Aux[i] + "'")
			return
		} else if r.ObjectClasses.Index(idx).Kind != 1 {
			err = errorTxt("dITContentRule: non-AUXILIARY class in AUX clause: '" +
				def.Aux[i] + "'")
			return
		}
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
	var def *DITContentRule
	if def, err = assertDITContentRule(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.ObjectClasses.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	// placeholder dcr dep scanner, as dcrs don't really
	// have dependents.
	err = r.DITContentRules.unregister(idx, def, nil)
	return
}

func assertNameForm(x any) (def *NameForm, err error) {
	switch tv := x.(type) {
	case NameForm:
		def = &tv
	case *NameForm:
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
	var def *NameForm
	if def, err = assertNameForm(input); err != nil {
		return
	}

	oc, idx := r.ObjectClasses.Get(def.OC)
	if idx == -1 || oc.Kind != 0 {
		err = errorTxt("nameForm: Unknown or invalid structural class OID: '" +
			def.OC + "'")
		return
	}

	if _, idx = r.NameForms.Get(def.NumericOID); idx != -1 {
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
			if _, idx := r.AttributeTypes.Get(at); idx == -1 {
				err = errorTxt("nameForm: Unknown " + clause +
					" attribute type: '" + at + "'")
				return
			}
		}
	}

	r.Push(def)

	return
}

func (r *SubschemaSubentry) nameFormDepScan(def *NameForm) (err error) {
	for i := 0; i < r.DITStructureRules.Len(); i++ {
		if cand := r.DITStructureRules.Index(i); strInSlice(cand.Form,
			append([]string{def.NumericOID}, def.Name...)) {
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
	var def *NameForm
	if def, err = assertNameForm(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.NameForms.Get(def.NumericOID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	err = r.NameForms.unregister(idx, def, r.nameFormDepScan)
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
	var def *DITStructureRule
	if def, err = assertDITStructureRule(input); err != nil {
		return
	}
	def.schema = r

	_, idx := r.DITStructureRules.Get(def.RuleID)
	if idx == -1 {
		err = errorTxt(def.Type() + " not found")
		return
	}

	err = r.DITStructureRules.unregister(idx, def, r.dITStructureRuleDepScan)
	return
}

func (r *SubschemaSubentry) dITStructureRuleDepScan(def *DITStructureRule) (err error) {
	if deps := def.SubordinateStructureRules(); deps.Len() > 0 {
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
	var def *DITStructureRule
	if def, err = assertDITStructureRule(input); err != nil {
		return
	}

	if _, idx := r.DITStructureRules.Get(def.RuleID); idx != -1 {
		err = errorTxt("dITStructureRule: Duplicate registration: '" +
			def.RuleID + "'")
		return
	} else if _, idx := r.NameForms.Get(def.Form); idx == -1 {
		err = errorTxt("dITStructureRule: nameForm: Unknown name form OID: '" +
			def.Form + "'")
		return
	}

	// Make sure superior structure rules, if present, are sane.
	for i := 0; i < len(def.SuperRules); i++ {
		if _, idx := r.DITStructureRules.Get(def.SuperRules[i]); idx == -1 {
			// Allow recursive rules to be added (ignore
			// "Not Found" for current ruleid).
			if def.SuperRules[i] != def.RuleID {
				err = errorTxt("dITStructureRule: Unknown SUP (superior rule): '" +
					def.SuperRules[i] + "'")
				return
			}
		}
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
LDAPSyntax returns an instance of *[LDAPSyntax] alongside the associated
integer index. If not found, the index shall be -1 and the definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [LDAPSyntax] numeric OID, or the description text.

Note that if description text is used, neither whitespace nor case-folding
are significant in the matching process.
*/
func (r *SubschemaSubentry) LDAPSyntax(term string) (*LDAPSyntax, int) {
	return r.LDAPSyntaxes.Get(term)
}

/*
MatchingRule returns an instance of *[MatchingRule] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [MatchingRule] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) MatchingRule(term string) (*MatchingRule, int) {
	return r.MatchingRules.Get(term)
}

/*
MatchingRuleUse returns an instance of *[MatchingRuleUse] alongside
the associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [MatchingRuleUse] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) MatchingRuleUse(term string) (*MatchingRuleUse, int) {
	return r.MatchingRuleUses.Get(term)
}

/*
AttributeType returns an instance of *[AttributeType] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [AttributeType] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) AttributeType(term string) (*AttributeType, int) {
	return r.AttributeTypes.Get(term)
}

/*
NameForm returns an instance of *[NameForm] alongside the associated integer
index. If not found, the index shall be -1 and the schema definition shall
be unpopulated.

The input id value (identifier) should be the string representation of
the desired [NameForm] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) NameForm(term string) (*NameForm, int) {
	return r.NameForms.Get(term)
}

/*
ObjectClass returns an instance of *[ObjectClass] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired *[ObjectClass] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) ObjectClass(term string) (*ObjectClass, int) {
	return r.ObjectClasses.Get(term)
}

/*
DITContentRule returns an instance of *[DITContentRule] alongside the associated
integer index. If not found, the index shall be -1 and the schema definition
shall be unpopulated.

The input id value (identifier) should be the string representation of the
desired [DITContentRule] numeric OID, or name (descriptor).

Note that if a name is used, case-folding is not significant in the matching
process.
*/
func (r *SubschemaSubentry) DITContentRule(term string) (*DITContentRule, int) {
	return r.DITContentRules.Get(term)
}

/*
DITStructureRule returns an instance of *[DITStructureRule] alongside the
associated integer index. If not found, the index shall be -1 and the
schema definition shall be unpopulated.

The input id value (identifier) should be the string representation of
the desired [DITStructureRule] integer identifier (rule ID), or name
(descriptor).

Note that if a name is used, case-folding is not significant in the
matching process.
*/
func (r *SubschemaSubentry) DITStructureRule(term string) (*DITStructureRule, int) {
	return r.DITStructureRules.Get(term)
}

/*
SubordinateStructureRules returns slices of [DITStructureRule], each of
which are direct subordinate structure rules of the receiver instance.
*/
func (r DITStructureRule) SubordinateStructureRules() (sub *DITStructureRules) {
	if r.schema != nil {
		sub = r.schema.NewDITStructureRules()
		for i := 0; i < r.schema.DITStructureRules.Len(); i++ {
			// NOTE - don't skip the superior rule itself,
			// as it may be a recursive (self-referencing)
			// structure rule.
			dsr := r.schema.DITStructureRules.Index(i)
			if strInSlice(append([]string{r.RuleID}, r.Name...), dsr.SuperRules) {
				sub.Push(dsr)
			}
		}
	}

	return
}

/*
SuperiorStructureRules returns slices of [DITStructureRule], each of
which are direct superior structure rules of the receiver instance.
*/
func (r DITStructureRule) SuperiorStructureRules() (sup *DITStructureRules) {
	if r.schema != nil {
		sup = r.schema.NewDITStructureRules()
		for i := 0; i < len(r.SuperRules); i++ {
			s := r.SuperRules[i]
			if dsr, idx := r.schema.DITStructureRules.Get(s); idx != -1 {
				sup.Push(dsr)
			}
		}
	}

	return
}

/*
NamedObjectClass returns an instance of [ObjectClass] which represents the
objectClass in use within the name form associated with the receiver instance.

The [ObjectClass], if found, is guaranteed to be of the STRUCTURAL kind.
*/
func (r DITStructureRule) NamedObjectClass() (noc *ObjectClass) {
	if r.schema != nil {
		noc = &ObjectClass{}
		if form, idx := r.schema.NameForms.Get(r.Form); idx != -1 {
			if oc, oidx := r.schema.ObjectClasses.Get(form.OC); oidx != -1 && oc.Kind == 0 {
				noc = oc
			}
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *LDAPSyntax) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *MatchingRule) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *AttributeType) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *MatchingRuleUse) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *ObjectClass) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *DITContentRule) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *NameForm) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *DITStructureRule) IsZero() bool { return r == nil }

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *LDAPSyntaxes) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *MatchingRules) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *AttributeTypes) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *MatchingRuleUses) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *ObjectClasses) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *DITContentRules) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *NameForms) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *DITStructureRules) IsZero() bool {
	var z bool
	if z = r == nil; !z {
		z = r.defs == nil
	}

	return z
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *LDAPSyntaxes) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *MatchingRules) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *AttributeTypes) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *MatchingRuleUses) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *ObjectClasses) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *DITContentRules) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *NameForms) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
setSchema assigns the provided instance of *[SubschemaSubentry] to the receiver
instance. The provided instance shall be used to verify any
*/
func (r *DITStructureRules) setSchema(schema *SubschemaSubentry) {
	r.schema = schema
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r LDAPSyntaxes) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r.Index(i).Match(id) {
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
*/
func (r *LDAPSyntaxes) Push(defs ...*LDAPSyntax) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *LDAPSyntaxes) unregister(idx int, def *LDAPSyntax,
	scanfunc func(*LDAPSyntax) error) (err error) {

	if err = scanfunc(def); err == nil {
		r.truncate(idx)
	}

	return
}

func (r *LDAPSyntaxes) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
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
*/
func (r *MatchingRules) Push(defs ...*MatchingRule) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *MatchingRules) unregister(idx int, def *MatchingRule,
	scanfunc func(*MatchingRule) error) (err error) {

	if err = scanfunc(def); err == nil {
		_, uidx := r.schema.MatchingRuleUses.Get(def.NumericOID)
		r.schema.MatchingRuleUses.truncate(uidx)
		r.truncate(idx)
	}

	return
}

func (r *MatchingRules) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
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
*/
func (r *AttributeTypes) Push(defs ...*AttributeType) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *AttributeTypes) unregister(idx int, def *AttributeType,
	scanfunc func(*AttributeType) error) (err error) {

	if err = scanfunc(def); err == nil {
		r.truncate(idx)
	}

	return
}

func (r *AttributeTypes) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
			idx = i
		}
	}

	return
}

/*
Contains returns an integer index value indicative of a [SchemaDefinition]
residing within the receiver instance which bears an identical value to id.
If not found, -1 is returned.
*/
func (r ObjectClasses) Contains(id string) (idx int) {
	idx = -1
	for i := 0; i < r.Len() && idx == -1; i++ {
		if r.Index(i).Match(id) {
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
*/
func (r *ObjectClasses) Push(defs ...*ObjectClass) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *ObjectClasses) unregister(idx int, def *ObjectClass,
	scanfunc func(*ObjectClass) error) (err error) {

	if err = scanfunc(def); err == nil {
		r.truncate(idx)
	}

	return
}

func (r *ObjectClasses) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
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
*/
func (r *DITContentRules) Push(defs ...*DITContentRule) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *DITContentRules) unregister(idx int, _ *DITContentRule,
	_ func(*DITContentRule) error) (err error) {
	r.truncate(idx)

	return
}

func (r *DITContentRules) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
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
*/
func (r *NameForms) Push(defs ...*NameForm) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *NameForms) unregister(idx int, def *NameForm,
	scanfunc func(*NameForm) error) (err error) {

	if err = scanfunc(def); err == nil {
		r.truncate(idx)
	}

	return
}

func (r *NameForms) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
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
		if r.Index(i).Match(id) {
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
*/
func (r *DITStructureRules) Push(defs ...*DITStructureRule) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.RuleID) == -1 {
			def.schema = r.schema
			r.defs = append(r.defs, def)
		}
	}
}

func (r *DITStructureRules) unregister(idx int, def *DITStructureRule,
	scanfunc func(*DITStructureRule) error) (err error) {

	if err = scanfunc(def); err == nil {
		r.truncate(idx)
	}

	return
}

func (r *DITStructureRules) truncate(idx int) {
	r.lock()
	defer r.unlock()

	if 0 <= idx && idx < r.Len() {
		r.defs = append(r.defs[:idx], r.defs[idx+1:]...)
	}
}

/*
SuperClassOf returns a Boolean value indicative of r being a superior ("SUP")
[ObjectClass] of sub, which may be a string or bonafide instance of
[ObjectClass].

Note: this will trace all super class chains indefinitely and, thus, will
recognize any superior association without regard for "depth".
*/
func (r ObjectClass) SuperClassOf(sub any) (sup bool) {
	var subordinate *ObjectClass
	switch tv := sub.(type) {
	case string:
		// resolve to ObjectClass
		var idx int
		if subordinate, idx = r.schema.ObjectClasses.Get(tv); idx == -1 {
			return
		}
	case *ObjectClass:
		subordinate = tv
	default:
		return
	}

	dsups := subordinate.SuperClasses
	for i := 0; i < len(dsups) && !sup; i++ {
		res, ridx := r.schema.ObjectClasses.Get(dsups[i])
		if ridx != -1 {
			if sup = (res.NumericOID == r.NumericOID || r.SuperClassOf(res)); sup {
				// direct (immediate) match by numeric OID or (indirect) traversal
				break
			}
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
type LDAPSyntaxes struct {
	defs   []*LDAPSyntax
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [LDAPSyntax] instances within the receiver.
*/
func (r LDAPSyntaxes) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = []string{def.Description}
	}

	return
}

/*
Index returns the Nth [LDAPSyntaxes] instances found within the
receiver instance.
*/
func (r *LDAPSyntaxes) Index(idx int) (def *LDAPSyntax) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPSyntaxes) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[LDAPSyntax] and a slice index following a
description or numeric OID match attempt. A zero instance of *[LDAPSyntax]
alongside an index of -1 is returned if no match is found.

Neither whitespace nor case is significant in the matching process when
a description is used.
*/
func (r LDAPSyntaxes) Get(term string) (def *LDAPSyntax, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
			idx = i
		}
	}

	return
}

/*
LDAPSyntaxByIndex returns the Nth [LDAPSyntax] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) LDAPSyntaxByIndex(idx int) (def *LDAPSyntax) {
	def = r.LDAPSyntaxes.Index(idx)
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
	schema      *SubschemaSubentry // internal ptr to schema
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
originates.

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
type MatchingRules struct {
	defs   []*MatchingRule
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [MatchingRule] instances within the receiver.
*/
func (r MatchingRules) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
Index returns the Nth [MatchingRule] instances found within the
receiver instance.
*/
func (r *MatchingRules) Index(idx int) (def *MatchingRule) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[MatchingRule] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[MatchingRule]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRules) Get(term string) (def *MatchingRule, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
			idx = i
		}
	}

	return
}

/*
MatchingRuleIndex returns the Nth [MatchingRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) MatchingRuleByIndex(idx int) (def *MatchingRule) {
	def = r.MatchingRules.Index(idx)
	return
}

/*
MatchingRuleUseIndex returns the Nth [MatchingRuleUse] instances
found within the receiver instance.
*/
func (r *SubschemaSubentry) MatchingRuleUseByIndex(idx int) (def *MatchingRuleUse) {
	def = r.MatchingRuleUses.Index(idx)
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
	schema      *SubschemaSubentry // internal ptr to schema
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
	err = invalidMR
	if r.isEqualityRule() {
		result, err = r.executeAssertion(actual, assertion)
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
	err = invalidMR
	if r.isSubstringRule() {
		result, err = r.executeAssertion(actual, assertion)
	}

	return
}

/*
OrderingMatch returns a [Boolean] instance alongside an error following an
attempt to compare the actual and assertion input values in terms of ordering.

Comparison behavior is dictated through use the operator input byte value.
See the [GreaterOrEqual] and [LessOrEqual] constants for details.

The actual value represents the value that would ostensibly be derived from
an LDAP DIT entry, while the assertion value represents the test value that
would be input by a requesting user.
*/
func (r MatchingRule) OrderingMatch(actual, assertion any, operator byte) (result Boolean, err error) {
	err = invalidMR
	if r.isOrderingRule() {
		result, err = r.executeAssertion(actual, assertion, operator)
	}

	return
}

/*
executeAssertion is the private handler method for EQUALITY, SUBSTR and
ORDERING matching rule operations.
*/
func (r MatchingRule) executeAssertion(actual, assertion any, operator ...byte) (result Boolean, err error) {
	if funk, found := matchingRuleAssertions[r.NumericOID]; found {
		err = invalidMR

		switch funk.kind() {
		case `EQUALITY`:
			result, err = funk.(EqualityRuleAssertion)(actual, assertion)
		case `SUBSTR`:
			result, err = funk.(SubstringsRuleAssertion)(actual, assertion)
		case `ORDERING`:
			if len(operator) == 1 {
				result, err = funk.(OrderingRuleAssertion)(actual, assertion, operator[0])
			}
		}
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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
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
func (r MatchingRule) newMatchingRuleUse() *MatchingRuleUse {
	return &MatchingRuleUse{
		NumericOID:  r.NumericOID,
		Name:        r.Name,
		Description: r.Description,
		Extensions:  r.Extensions,
	}
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
type AttributeTypes struct {
	defs   []*AttributeType
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [AttributeType] instances within the receiver.
*/
func (r AttributeTypes) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.5" per [§ 4.2.2 of RFC 4512].

[§ 4.2.2 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.2
*/
func (r AttributeTypes) OID() string { return `2.5.21.5` }

/*
Index returns the Nth [AttributeType] instances found within the
receiver instance.
*/
func (r *AttributeTypes) Index(idx int) (def *AttributeType) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r AttributeTypes) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[AttributeType] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[AttributeType]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r AttributeTypes) Get(term string) (def *AttributeType, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
			idx = i
		}
	}

	return
}

/*
AttributeTypeIndex returns the Nth [AttributeType] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) AttributeTypeByIndex(idx int) (def *AttributeType) {
	def = r.AttributeTypes.Index(idx)
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

	schema *SubschemaSubentry // internal ptr to schema
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
func (r AttributeType) SuperChain() (supers *AttributeTypes) {
	supers = &AttributeTypes{}
	if r.schema != nil {
		supers = r.schema.NewAttributeTypes()
		if sup, idx := r.schema.AttributeTypes.Get(r.SuperType); idx != -1 {
			supers.defs = append(supers.defs, sup.SuperChain().defs...)
			supers.Push(sup)
		}
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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
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
type MatchingRuleUses struct {
	defs   []*MatchingRuleUse
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [MatchingRuleUse] instances within the receiver.
*/
func (r MatchingRuleUses) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
Index returns the Nth [MatchingRuleUse] instances found within the
receiver instance.
*/
func (r *MatchingRuleUses) Index(idx int) (def *MatchingRuleUse) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
push is a private method which appends one or more instances of
MatchingRuleUse to the receiver instance.

This method is private as the concept of managing MatchingRuleUse
instances is purely an internal function, triggered via certain actions
taken upon associated instances of MatchingRules and AttributeTypes.
*/
func (r *MatchingRuleUses) push(defs ...*MatchingRuleUse) {
	r.lock()
	defer r.unlock()

	for i := 0; i < len(defs); i++ {
		def := defs[i]
		if def.Valid() && r.Contains(def.NumericOID) == -1 {
			r.defs = append(r.defs, def)
		}
	}
}

/*
String returns the string representation of the receiver instance.
*/
func (r MatchingRuleUses) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		if def := r.Index(i); def.String() != "" {
			s += r.Type() + `: ` + def.String() + string(rune(10))
		}
	}

	return
}

/*
Get returns an instance of *[MatchingRuleUse] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[MatchingRuleUse]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r MatchingRuleUses) Get(term string) (def *MatchingRuleUse, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
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
	schema      *SubschemaSubentry // internal ptr to schema
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
originates.

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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
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
type ObjectClasses struct {
	defs   []*ObjectClass
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [ObjectClass] instances within the receiver.
*/
func (r ObjectClasses) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
Index returns the Nth [ObjectClass] instances found within the
receiver instance.
*/
func (r *ObjectClasses) Index(idx int) (def *ObjectClass) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.6" per [§ 4.2.1 of RFC 4512].

[§ 4.2.1 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.1
*/
func (r ObjectClasses) OID() string { return `2.5.21.6` }

/*
ObjectClassIndex returns the Nth [ObjectClass] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) ObjectClassByIndex(idx int) (def *ObjectClass) {
	def = r.ObjectClasses.Index(idx)
	return
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
func (r ObjectClass) SubordinateClasses() (sub *ObjectClasses) {
	if r.schema != nil {
		sub = r.schema.NewObjectClasses()
		for i := 0; i < r.schema.ObjectClasses.Len(); i++ {
			oc := r.schema.ObjectClasses.Index(i)
			if strInSlice(append([]string{r.NumericOID}, r.Name...), oc.SuperClasses) {
				sub.Push(oc)
			}
		}
	}

	return
}

/*
SuperiorClasses returns slices of *[ObjectClass], each of which are direct
superior object classes of the input string id.

The input string id must be the numeric OID or name of the subordinate
object class.

Note that if a name is used, case-folding is not significant in the
matching process.

If zero slices are returned, this can mean either the object class was
not found, or that it has no superior classes of its own.
*/
func (r ObjectClass) SuperiorClasses() (sup *ObjectClasses) {
	sup = &ObjectClasses{}
	if r.schema != nil {
		sup = r.schema.NewObjectClasses()
		for i := 0; i < len(r.SuperClasses); i++ {
			s := r.SuperClasses[i]
			if oc, sidx := r.schema.ObjectClasses.Get(s); sidx != -1 {
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
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[ObjectClass] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[ObjectClass]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r ObjectClasses) Get(term string) (def *ObjectClass, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
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

	schema *SubschemaSubentry // internal ptr to schema
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
func (r ObjectClass) SuperChain() (supers *ObjectClasses) {
	supers = &ObjectClasses{}
	if r.schema != nil {
		supers = r.schema.NewObjectClasses()
		for _, class := range r.SuperClasses {
			if def, idx := r.schema.ObjectClasses.Get(class); idx != -1 {
				supers.Push(def)
			}
		}

		supers.Push(&r)
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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
}

func stringClassKind(kind uint8) (k string) {
	k = ` STRUCTURAL` // default
	if 1 <= kind && kind <= 2 {
		if kind == 1 {
			k = ` AUXILIARY`
		} else if kind == 2 {
			k = ` ABSTRACT`
		}
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
AllMust returns an *[AttributeTypes] instance containing zero (0)
or more MANDATORY *[AttributeType] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered *[AttributeType]
slice instances known to be registered within the relevant *[SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
*[ObjectClass] instances known to be registered within that same
*[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClass) AllMust() (must *AttributeTypes) {
	must = r.schema.NewAttributeTypes()

	// Add MANDATORY types declared by super classes.
	for i := 0; i < len(r.SuperClasses); i++ {
		sm := r.SuperClasses[i]
		if class, idx := r.schema.ObjectClasses.Get(sm); idx != -1 {
			for _, j := range class.AllMust().defs {
				must.Push(j)
			}
		}
	}

	// Add local MANDATORY types.
	for i := 0; i < len(r.Must); i++ {
		if attr, idx := r.schema.AttributeTypes.Get(r.Must[i]); idx != -1 {
			must.Push(attr)
		}
	}

	return
}

/*
AllMay returns an *[AttributeTypes] instance containing zero (0)
or more OPTIONAL *[AttributeType] instances for use with this the
receiver instance, as well as those specified by any and all applicable super
classes.

The input types instance must contain all registered *[AttributeType]
slice instances known to be registered within the relevant *[SubschemaSubentry]
instance. Similarly, the input classes instance must contain all registered
*[ObjectClass] instances known to be registered within that same
*[SubschemaSubentry] instance.

Duplicate references are silently discarded.
*/
func (r ObjectClass) AllMay() (may *AttributeTypes) {
	may = r.schema.NewAttributeTypes()

	// Add MANDATORY types declared by super classes.
	for i := 0; i < len(r.SuperClasses); i++ {
		sm := r.SuperClasses[i]
		if class, idx := r.schema.ObjectClasses.Get(sm); idx != -1 {
			for _, j := range class.AllMay().defs {
				may.Push(j)
			}
		}
	}

	// Add local MANDATORY types.
	for i := 0; i < len(r.May); i++ {
		if attr, idx := r.schema.AttributeTypes.Get(r.May[i]); idx != -1 {
			may.Push(attr)
		}
	}

	return
}

/*
DITContentRules implements [§ 4.2.6 of RFC 4512] and contains slices of
[DITContentRule].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
type DITContentRules struct {
	defs   []*DITContentRule
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [DITContentRule] instances within the receiver.
*/
func (r DITContentRules) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
Index returns the Nth [DITContentRule] instances found within the
receiver instance.
*/
func (r *DITContentRules) Index(idx int) (def *DITContentRule) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.2" per [§ 4.2.6 of RFC 4512].

[§ 4.2.6 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.6
*/
func (r DITContentRules) OID() string { return `2.5.21.2` }

/*
DITContentRuleIndex returns the Nth [DITContentRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) DITContentRuleByIndex(idx int) (def *DITContentRule) {
	def = r.DITContentRules.Index(idx)
	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITContentRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[DITContentRule] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[DITContentRule]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITContentRules) Get(term string) (def *DITContentRule, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
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

	schema *SubschemaSubentry // internal ptr to schema
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
originates.

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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r DITContentRule) Valid() bool {

	var total, valid int
	for _, clauses := range append([][]string{r.Aux}, r.Must,
		r.May, r.Not, []string{r.NumericOID}) {
		for _, id := range clauses {
			total++
			if oID(id).True() {
				valid++
			}
		}
	}

	// Ensure each clause value was a valid
	// numeric OID or descriptor.
	badSyntax := total != valid

	// Make sure MUST and MAY attributes
	// do not appear in NOT clause.
	conflict := strInSlice(append(r.Must, r.May...), r.Not)

	return !conflict && !badSyntax
}

/*
NameForms implements [§ 4.2.8 of RFC 4512] and contains slices of
[NameForm].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
type NameForms struct {
	defs   []*NameForm
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [NameForm] instances within the receiver.
*/
func (r NameForms) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.NumericOID] = def.Name
	}

	return
}

/*
Index returns the Nth [NameForm] instances found within the
receiver instance.
*/
func (r *NameForms) Index(idx int) (def *NameForm) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.7" per [§ 4.2.8 of RFC 4512].

[§ 4.2.8 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.8
*/
func (r NameForms) OID() string { return `2.5.21.7` }

/*
NameFormIndex returns the Nth [NameForm] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) NameFormByIndex(idx int) (def *NameForm) {
	def = r.NameForms.Index(idx)
	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r NameForms) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[NameForm] and a slice index following
a descriptor or numeric OID match attempt. A zero instance of *[NameForm]
alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r NameForms) Get(term string) (def *NameForm, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
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

	schema *SubschemaSubentry // internal ptr to schema
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
originates.

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
	return strInSlice(term, append([]string{r.NumericOID}, r.Name...))
}

/*
Valid returns a Boolean value indicative of a syntactically valid receiver
instance. Note this does not verify the presence of dependency schema elements.
*/
func (r NameForm) Valid() bool {
	var total, valid int
	for _, clauses := range append([][]string{{r.NumericOID, r.OC}}, r.Must, r.May) {
		for _, id := range clauses {
			total++
			if oID(id).True() {
				valid++
			}
		}
	}

	// Verify each above clause slice is a valid
	// numeric OID or descriptor.
	badSyntax := total != valid

	// Make sure MUST and MAY attributes
	// do not overlap. This is fine for
	// classes, but not name forms.
	conflict := strInSlice(r.May, r.Must)

	return !conflict && !badSyntax
}

/*
DITStructureRules implements [§ 4.2.7 of RFC 4512] and contains slices of
[DITStructureRule].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
type DITStructureRules struct {
	defs   []*DITStructureRule
	mutex  *sync.Mutex
	schema *SubschemaSubentry // internal ptr to schema
}

/*
Inventory returns an instance of [SchemaDefinitionTable] which represents the current
inventory of [DITStructureRule] instances within the receiver.
*/
func (r DITStructureRules) Table() (table SchemaDefinitionTable) {
	table = make(SchemaDefinitionTable, 0)
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		table[def.RuleID] = def.Name
	}

	return
}

/*
Index returns the Nth [DITStructureRule] instances found within the
receiver instance.
*/
func (r *DITStructureRules) Index(idx int) (def *DITStructureRule) {
	if 0 <= idx && idx < r.Len() {
		def = r.defs[idx]
	}

	return
}

/*
OID returns the numeric OID literal "2.5.21.1" per [§ 4.2.7 of RFC 4512].

[§ 4.2.7 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-4.2.7
*/
func (r DITStructureRules) OID() string { return `2.5.21.1` }

/*
DITStructureRuleIndex returns the Nth [DITStructureRule] instances found
within the receiver instance.
*/
func (r *SubschemaSubentry) DITStructureRuleByIndex(idx int) (def *DITStructureRule) {
	def = r.DITStructureRules.Index(idx)
	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r DITStructureRules) String() (s string) {
	for i := 0; i < r.Len(); i++ {
		def := r.Index(i)
		s += r.Type() + `: ` + def.String() + string(rune(10))
	}

	return
}

/*
Get returns an instance of *[DITStructureRule] and a slice index following
a descriptor or integer identifier match attempt. A zero instance of
*[DITStructureRule] alongside an index of -1 is returned if no match is found.

Case is not significant in the matching process.
*/
func (r DITStructureRules) Get(term string) (def *DITStructureRule, idx int) {
	idx = -1

	for i := 0; i < r.Len() && idx == -1; i++ {
		x := r.Index(i)
		if x.Match(term) {
			def = x
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

	schema *SubschemaSubentry // internal ptr to schema
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
func (r *DITStructureRule) Identifier() (id string) {
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
originates.

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
	return strInSlice(term, append([]string{r.RuleID}, r.Name...))
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

func marshalLDAPSyntax(x any) (def *LDAPSyntax, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("ldapSyntax")
		return
	}

	def = new(LDAPSyntax)
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

func marshalMatchingRule(x any) (def *MatchingRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("matchingRuleUse")
		return
	}

	def = new(MatchingRule)
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

func marshalMatchingRuleUse(x any) (def *MatchingRuleUse, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("matchingRuleUse")
		return
	}

	def = new(MatchingRuleUse)
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

func marshalAttributeType(x any) (def *AttributeType, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("attributeType")
		return
	}

	def = new(AttributeType)
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

func assertObjectClass(x any) (def *ObjectClass, err error) {
	switch tv := x.(type) {
	case ObjectClass:
		def = &tv
	case *ObjectClass:
		def = tv
	default:
		def, err = marshalObjectClass(tv)
	}

	return
}

func marshalObjectClass(x any) (def *ObjectClass, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("objectClass")
		return
	}

	def = new(ObjectClass)
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

func assertDITContentRule(x any) (def *DITContentRule, err error) {
	switch tv := x.(type) {
	case DITContentRule:
		def = &tv
	case *DITContentRule:
		def = tv
	default:
		def, err = marshalDITContentRule(tv)
	}

	return
}

func marshalDITContentRule(x any) (def *DITContentRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("dITContentRule")
		return
	}

	def = new(DITContentRule)
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

func marshalNameForm(x any) (def *NameForm, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("nameForm")
		return
	}

	def = new(NameForm)
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

func assertDITStructureRule(x any) (def *DITStructureRule, err error) {
	switch tv := x.(type) {
	case DITStructureRule:
		def = &tv
	case *DITStructureRule:
		def = tv
	default:
		def, err = marshalDITStructureRule(tv)
	}

	return
}

func marshalDITStructureRule(x any) (def *DITStructureRule, err error) {
	var input string

	switch tv := x.(type) {
	case []byte:
		input = string(tv)
	case string:
		input = tv
	default:
		err = errorBadType("dITStructureRule")
		return
	}

	def = new(DITStructureRule)
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

func (r LDAPSyntaxes) Len() int      { return len(r.defs) }
func (r MatchingRules) Len() int     { return len(r.defs) }
func (r AttributeTypes) Len() int    { return len(r.defs) }
func (r MatchingRuleUses) Len() int  { return len(r.defs) }
func (r ObjectClasses) Len() int     { return len(r.defs) }
func (r DITContentRules) Len() int   { return len(r.defs) }
func (r NameForms) Len() int         { return len(r.defs) }
func (r DITStructureRules) Len() int { return len(r.defs) }

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
