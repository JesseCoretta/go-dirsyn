package dirsyn

import (
	"fmt"
	"testing"
)

func ExampleSubschemaSubentry_ReadBytes() {
	// Assume raw was read from a file somewhere ...
	raw := []byte(`
	attributeTypes: ( 1.3.6.1.4.1.56521.999.9.5
		NAME 'fakeAttribute'
		SUP name )
	attributeTypes: ( 1.3.6.1.4.1.56521.999.9.6
		NAME 'otherAttribute'
		SUP o )
	objectClasses:  ( 1.3.6.1.4.1.56521.999.10.1
		NAME 'testClass'
		DESC 'a fake class'
		MUST cn
		MAY ( fakeAttribute $ otherAttribute ) )
	`)

	if err := exampleSchema.ReadBytes(raw); err != nil {
		fmt.Println(err)
		return
	}
	// Output:
}

func ExampleSubschemaSubentry_Counters() {
	fmt.Println(exampleSchema.Counters())
	// Output: [67 44 96 44 29 0 1 2 283]
}

func ExampleAttributeType_SuperChain() {
	child, _ := exampleSchema.AttributeType(`cn`)
	supers := child.SuperChain(exampleSchema.AttributeTypes)
	fmt.Println(supers)
	// Output: attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
}

func ExampleDITStructureRule_SubRules() {
	rules := exampleSchema.DITStructureRules
	sup, idx := rules.Get(`applicationProcessStructure`)
	if idx == -1 {
		// not found
		return
	}

	subs := sup.SubRules(rules)
	fmt.Printf("%d subordinate rule found", len(subs))
	// Output: 1 subordinate rule found
}

func ExampleObjectClass_SuperClassOf() {
	classes := exampleSchema.ObjectClasses
	top, idx := classes.Get(`top`) // 2.5.6.0
	if idx == -1 {
		// not found
		return
	}

	fmt.Println(top.SuperClassOf(`subentry`, classes))
	// Output: true
}

func ExampleObjectClass_SuperChain() {
	child, _ := exampleSchema.ObjectClass(`subentry`)
	supers := child.SuperChain(exampleSchema.ObjectClasses)
	fmt.Println(supers)
	// Output: objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )
}

func ExampleObjectClass_AllMust() {
	child, _ := exampleSchema.ObjectClass(`subentry`)
	musts := child.AllMust(exampleSchema.AttributeTypes,
		exampleSchema.ObjectClasses)
	fmt.Println(musts)
	// Output:
	// attributeTypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
	// attributeTypes: ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )
	// attributeTypes: ( 2.5.18.6 NAME 'subtreeSpecification' SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 SINGLE-VALUE USAGE directoryOperation )
}

func ExampleObjectClass_AllMay() {
	child, _ := exampleSchema.ObjectClass(`applicationProcess`)
	musts := child.AllMay(exampleSchema.AttributeTypes,
		exampleSchema.ObjectClasses)
	fmt.Println(musts)
	// Output:
	// attributeTypes: ( 2.5.4.34 NAME 'seeAlso' SUP distinguishedName )
	// attributeTypes: ( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )
	// attributeTypes: ( 2.5.4.7 NAME ( 'l' 'localityName' ) SUP name )
	// attributeTypes: ( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
}

func ExampleSubschemaSubentry_LDAPSyntax() {
	def, idx := exampleSchema.LDAPSyntax(`INTEGER`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	fmt.Println(def.NumericOID)
	// Output: 1.3.6.1.4.1.1466.115.121.1.27
}

func ExampleMatchingRule_Match() {
	def, idx := exampleSchema.MatchingRule(`2.5.13.2`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}
	fmt.Println(def.Match(`caseIgnoreMatch`)) // or by numeric OID (2.5.13.2)
	// Output: true
}

func ExampleLDAPSyntax_HR() {
	def, idx := exampleSchema.LDAPSyntax(`1.3.6.1.1.15.5`) // X.509 Cert List Exact Assertion
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	fmt.Println(def.HR())
	// Output: false
}

func ExampleLDAPSyntax_Verify() {
	def, idx := exampleSchema.LDAPSyntax(`INTEGER`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	result := def.Verify(`362`) // verify "362" as an INTEGER ASN.1 type
	fmt.Println(result)
	// Output: TRUE
}

func ExampleSubschemaSubentry_RegisterLDAPSyntax_byDescription() {
	// Invent and register a custom (non-standard) syntax
	exampleSchema.RegisterLDAPSyntax(`ldapSyntaxes: ( 1.3.6.1.4.1.56521.101.2.1.4
          DESC 'ObjectIdentifierValue'
          X-PATTERN '^\{([a-z](-?[A-Za-z0-9]+)*(\(\d+\))?)(\s([a-z](-?[A-Za-z0-9]+)*(\(\d+\))))*\}$' )`)

	// Retrieve new syntax
	def, idx := exampleSchema.LDAPSyntax(`object identifier value`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	// Verify assertion value against syntax
	fmt.Println(def.Verify(`{joint-iso-itu-t(2) uuid(25)}`))
	// Output: TRUE
}

func ExampleSubschemaSubentry_RegisterLDAPSyntax_byInstance() {
	instance := LDAPSyntax{
		NumericOID:  `1.3.6.1.4.1.56521.999.2.1.4`,
		Description: `Custom Syntax`,
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterLDAPSyntax(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.LDAPSyntax("custom syntax"); idx != -1 {
		fmt.Println("Syntax found")
	}
	// Output: Syntax found
}

func ExampleSubschemaSubentry_RegisterMatchingRule_byInstance() {
	instance := MatchingRule{
		NumericOID:  `1.3.6.1.4.1.56521.999.11.2.4`,
		Name:        []string{`myMatchingRule`},
		Description: `Some matching rule`,
		Syntax:      `1.3.6.1.4.1.1466.115.121.1.15`,
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterMatchingRule(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.MatchingRule("mymatchingrule"); idx != -1 {
		fmt.Println("Rule found")
	}
	// Output: Rule found
}

func ExampleSubschemaSubentry_RegisterAttributeType_byInstance() {
	instance := AttributeType{
		NumericOID:  `1.3.6.1.4.1.56521.999.11.2.4`,
		Name:        []string{`myAttribute`},
		Description: `A random attribute`,
		Syntax:      `1.3.6.1.4.1.1466.115.121.1.15`,
		Equality:    `caseIgnoreMatch`,
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterAttributeType(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.AttributeType("myattribute"); idx != -1 {
		fmt.Println("Type found")
	}
	// Output: Type found
}

func ExampleSubschemaSubentry_RegisterObjectClass_byInstance() {
	instance := ObjectClass{
		NumericOID:  `1.3.6.1.4.1.56521.999.17.1.64`,
		Name:        []string{`myClass`},
		Description: `An auxiliary class`,
		Kind:        uint8(1),
		Must:        []string{`cn`, `l`},
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterObjectClass(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.ObjectClass("myclass"); idx != -1 {
		fmt.Println("Class found")
	}
	// Output: Class found
}

func ExampleSubschemaSubentry_RegisterDITContentRule_byInstance() {
	instance := DITContentRule{
		NumericOID:  `2.5.6.11`,
		Name:        []string{`myContentRule`},
		Description: `A dITContentRule`,
		Must:        []string{`cn`, `l`},
		Not:         []string{`seeAlso`},
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterDITContentRule(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.DITContentRule("myContentRule"); idx != -1 {
		fmt.Println("Rule found")
	}
	// Output: Rule found
}

func ExampleSubschemaSubentry_RegisterNameForm_byInstance() {
	instance := NameForm{
		NumericOID:  `2.5.15.16`,
		Name:        []string{`subentryNameForm`},
		Description: `X.501, cl. 14.2.2: the subentry name form`,
		OC:          `subentry`,
		Must:        []string{`cn`},
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`X.501`},
			},
		},
	}

	if err := exampleSchema.RegisterNameForm(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.NameForm("2.5.15.16"); idx != -1 {
		fmt.Println("Name form found")
	}
	// Output: Name form found
}

func ExampleSubschemaSubentry_RegisterDITStructureRule_byInstance() {
	instance := DITStructureRule{
		RuleID:      `3`,
		Name:        []string{`subentryStructureRule`},
		Description: `Enforces ITU-T X.501 cl. 14.2.2; internal use only`,
		Form:        `subentryNameForm`,
		SuperRules:  []string{`1`, `2`},
		Extensions: map[int]Extension{
			0: {
				XString: `X-ORIGIN`,
				Values:  []string{`NOWHERE`},
			},
		},
	}

	if err := exampleSchema.RegisterDITStructureRule(instance); err != nil {
		fmt.Println(err)
		return
	}

	if _, idx := exampleSchema.DITStructureRule("3"); idx != -1 {
		fmt.Println("Rule found")
	}
	// Output: Rule found
}

func ExampleSubschemaSubentry_NamedObjectClass() {
	noc, idx := exampleSchema.NamedObjectClass(`2`)
	if idx == -1 {
		fmt.Println("Structure Rule #2 not found")
		return
	}

	fmt.Println(noc.NumericOID)
	// Output: 2.5.6.11
}

func ExampleSubschemaSubentry_MatchingRule() {
	mr, idx := exampleSchema.MatchingRule(`caseExactMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	fmt.Println(mr.NumericOID)
	// Output: 2.5.13.5
}

func ExampleMatchingRule_EqualityMatch_caseExactMatch() {
	// obtain caseExactMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`caseExactMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	matched, err := mr.EqualityMatch(`thisIsText`, `ThisIsText`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: FALSE
}

func ExampleMatchingRule_EqualityMatch_integerMatch() {
	// obtain integerMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`integerMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	matched, err := mr.EqualityMatch(2, 22)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: FALSE
}

func ExampleMatchingRule_SubstringsMatch_caseExactSubstringsMatch() {
	// obtain caseExactSubstringsMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`caseExactSubstringsMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	matched, err := mr.SubstringsMatch(`thisIsText`, `*HisIsT*xt`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: FALSE
}

func ExampleMatchingRule_OrderingMatch_integerOrderingMatchGreaterOrEqual() {
	// obtain integerOrderingMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`integerOrderingMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	// Greater or equal (1>=2)
	matched, err := mr.OrderingMatch(1, 2, GreaterOrEqual)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: TRUE
}

func ExampleMatchingRule_OrderingMatch_integerOrderingMatchLessOrEqual() {
	// obtain integerOrderingMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`integerOrderingMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	// Less or equal (1<=2)
	matched, err := mr.OrderingMatch(1, 2, LessOrEqual)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: TRUE
}

func ExampleMatchingRule_OrderingMatch_caseExactOrderingMatchGreaterOrEqual() {
	// obtain caseExactOrderingMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`caseExactOrderingMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	// Greater or equal (actual>=assertion)
	matched, err := mr.OrderingMatch(`ThisIsText`, `thisIsText`, GreaterOrEqual)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: FALSE
}

func ExampleMatchingRule_OrderingMatch_caseExactOrderingMatchLessOrEqual() {
	// obtain caseExactOrderingMatch matchingRule instance
	mr, idx := exampleSchema.MatchingRule(`caseExactOrderingMatch`)
	if idx == -1 {
		fmt.Println("No such definition found")
		return
	}

	// Less or equal (actual<=assertion)
	matched, err := mr.OrderingMatch(`thisIsText`, `ThisIsText`, LessOrEqual)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(matched)
	// Output: TRUE
}

func ExampleSubschemaSubentry_SuperiorStructureRules() {
	sups := exampleSchema.SuperiorStructureRules(`applicationProcessStructure`)
	fmt.Printf("Rule is a root: %t", len(sups) == 0)
	// Output: Rule is a root: true
}

func ExampleSubschemaSubentry_SubordinateStructureRules() {
	subs := exampleSchema.SubordinateStructureRules(`applicationProcessStructure`)
	fmt.Printf("Number of subordinate rules: %d", len(subs))
	// Output: Number of subordinate rules: 2
}

func TestSubschemaSubentry_codecov(t *testing.T) {

	_ = exampleSchema.OID()
	_ = exampleSchema.String()
	_ = exampleSchema.LDAPSyntaxes.OID()
	_ = exampleSchema.LDAPSyntaxes.Len()
	_ = exampleSchema.MatchingRules.OID()
	_ = exampleSchema.MatchingRules.Len()
	_ = exampleSchema.AttributeTypes.OID()
	_ = exampleSchema.AttributeTypes.Len()
	_ = exampleSchema.MatchingRuleUses.OID()
	_ = exampleSchema.MatchingRuleUses.Len()
	_ = exampleSchema.ObjectClasses.OID()
	_ = exampleSchema.ObjectClasses.Len()
	_ = exampleSchema.DITContentRules.OID()
	_ = exampleSchema.DITContentRules.Len()
	_ = exampleSchema.NameForms.OID()
	_ = exampleSchema.NameForms.Len()
	_ = exampleSchema.DITStructureRules.OID()
	_ = exampleSchema.DITStructureRules.Len()

	_ = exampleSchema.LDAPSyntaxByIndex(0)
	_ = exampleSchema.MatchingRuleByIndex(0)
	_ = exampleSchema.AttributeTypeByIndex(0)
	_ = exampleSchema.MatchingRuleUseByIndex(0)
	_ = exampleSchema.ObjectClassByIndex(0)
	_ = exampleSchema.DITContentRuleByIndex(0)
	_ = exampleSchema.NameFormByIndex(0)
	_ = exampleSchema.DITStructureRuleByIndex(0)

	var def Definition
	def, _ = exampleSchema.LDAPSyntax(`INTEGER`)
	_ = def.XOrigin()

	def, _ = exampleSchema.MatchingRule(`caseIgnoreMatch`)
	_ = def.XOrigin()

	def, _ = exampleSchema.AttributeType(`seeAlso`)
	_ = def.XOrigin()

	def, _ = exampleSchema.MatchingRuleUse(`caseIgnoreMatch`)
	_ = def.XOrigin()

	def, _ = exampleSchema.ObjectClass(`top`)
	_ = def.XOrigin()

	//_ = exampleSchema.DITContentRule(0)
	def, _ = exampleSchema.NameForm(`applicationProcessNameForm`)
	_ = def.XOrigin()

	def, _ = exampleSchema.DITStructureRule(`applicationProcessStructure`)
	_ = def.XOrigin()

	_ = exampleSchema.RegisterLDAPSyntax(nil)
	_ = exampleSchema.RegisterLDAPSyntax(LDAPSyntax{})
	_ = exampleSchema.RegisterLDAPSyntax(LDAPSyntax{
		NumericOID: `1.3.6.1.4.1.1466.115.121.1.15`,
	})
	_ = exampleSchema.RegisterMatchingRule(nil)
	_ = exampleSchema.RegisterMatchingRule(MatchingRule{})
	_ = exampleSchema.RegisterMatchingRule(MatchingRule{
		NumericOID: `2.5.13.2`,
		Syntax:     `1.3.6.1.4.1.1466.115.121.1.15`,
	})
	_ = exampleSchema.RegisterMatchingRule(MatchingRule{
		NumericOID: `2.5.13.222222`,
		Syntax:     `1.3.6.1.4.1.1466.115.121.1.15111`,
	})
	_ = exampleSchema.RegisterAttributeType(nil)
	_ = exampleSchema.RegisterAttributeType(AttributeType{})
	_ = exampleSchema.RegisterAttributeType(AttributeType{
		NumericOID: `2.5.4.3`,
		Name:       []string{`cn`},
		SuperType:  `name`,
	})
	_ = exampleSchema.RegisterAttributeType(AttributeType{
		NumericOID: `2.7.4.311111`,
		Name:       []string{`givenNames`},
		Equality:   `blarg`,
		Ordering:   `blarg`,
		Substring:  `blarg`,
	})
	_ = exampleSchema.RegisterAttributeType(AttributeType{
		NumericOID: `2.7.4.311111`,
		Name:       []string{`givenNames`},
		Syntax:     `blarg`,
	})
	_ = exampleSchema.RegisterAttributeType(AttributeType{
		NumericOID: `2.9.4.811111`,
		Name:       []string{`cn`},
		SuperType:  `1.2.3.4`,
	})
	_ = exampleSchema.RegisterObjectClass(nil)
	_ = exampleSchema.RegisterObjectClass(ObjectClass{})
	_ = exampleSchema.RegisterObjectClass(ObjectClass{
		NumericOID:   `2.7.4.311111`,
		Name:         []string{`classyClass`},
		Must:         []string{`blarg`},
		SuperClasses: []string{`crappyClass`},
	})
	_ = exampleSchema.RegisterObjectClass(ObjectClass{
		NumericOID:   `2.7.4.311111`,
		Name:         []string{`classyClass`},
		SuperClasses: []string{`crappyClass`},
	})
	_ = exampleSchema.RegisterObjectClass(ObjectClass{
		NumericOID:   `2.7.4.311111`,
		SuperClasses: []string{`top`},
		Kind:         uint8(4),
	})
	_ = exampleSchema.RegisterDITContentRule(nil)
	_ = exampleSchema.RegisterDITContentRule(DITContentRule{})

	// Try to load duplicates just for coverage purposes.
	_ = exampleSchema.RegisterAttributeType(testSchemaDefinitions[0])
	_ = exampleSchema.RegisterObjectClass(testSchemaDefinitions[10])
	_ = exampleSchema.RegisterNameForm(testSchemaDefinitions[13])
	_ = exampleSchema.RegisterDITStructureRule(testSchemaDefinitions[14])
	_ = exampleSchema.RegisterNameForm(nil)
	_ = exampleSchema.RegisterNameForm(NameForm{})
	_ = exampleSchema.RegisterNameForm(`( 1.3.6.1.4.1.56521.999.38.1.16
		OC appppplicationProcess )`)
	_ = exampleSchema.RegisterNameForm(`( 1.3.6.1.4.1.56521.999.38.1.16
		OC top
		MUST bogus )`)
	_ = exampleSchema.RegisterNameForm(`( 1.3.6.1.4.1.56521.999.38.1.16
		OC applicationProcess
		MUST bogus )`)
	_ = exampleSchema.RegisterDITStructureRule(nil)
	_ = exampleSchema.RegisterDITStructureRule(DITStructureRule{})

	_ = exampleSchema.SuperiorStructureRules(`2`)

	_ = exampleSchema.DITContentRules.Type()

	stringBooleanClause(`test`, true)
	stringBooleanClause(`test`, false)

	_ = lDAPSyntaxDescription(primerSyntaxes[0])
	_ = matchingRuleDescription(primerMatchingRules[0])
	_ = matchingRuleUseDescription(`( 2.5.13.10 NAME numericStringSubstringsMatch APPLIES zz )`)
	_ = attributeTypeDescription(testSchemaDefinitions[0])
	_ = objectClassDescription(testSchemaDefinitions[4])
	_ = dITContentRuleDescription(testSchemaDefinitions[10])
	_ = nameFormDescription(testSchemaDefinitions[12])
	_ = dITStructureRuleDescription(testSchemaDefinitions[13])

	exampleSchema.RegisterDITContentRule(`()`)

	var mru MatchingRuleUses
	mru = append(mru, MatchingRuleUse{
		NumericOID:  `2.5.13.15`,
		Description: `this is text`,
		Name:        []string{`userRule`},
		Applies:     []string{`cn`, `sn`},
	})
	_ = mru.String()
	mru.isDefinitions()

	var lss LDAPSyntaxes
	lss.isDefinitions()

	var mrs MatchingRules
	mrs.isDefinitions()

	var ats AttributeTypes
	ats.isDefinitions()

	var ocs ObjectClasses
	ocs.isDefinitions()

	var nfs NameForms
	nfs.isDefinitions()

	var dcs DITContentRules
	dcs.isDefinitions()

	var dss DITStructureRules
	dss.isDefinitions()

	var atd AttributeType
	atd.Single = true
	atd.OID()
	atd.mutexBooleanString()
	atd.handleBoolean(`COLLECTIVE`)
	atd.isDefinition()
	atd.Syntax = `1.3.6.1.4.1.1466.115.121.1.15`
	atd.MinUpperBounds = 32
	_, _, _ = trimAttributeSyntaxMUB(`1.3.6.1.4.1.1466.115.121.1.15{32}`)
	atd.Type()
	atd.Valid()
	_ = atd.String()
	_ = atd.syntaxMatchingRuleClauses()

	atd.Single = false
	atd.mutexBooleanString()
	atd.handleBoolean(`COLLECTIVE`)
	atd.handleBoolean(`SINGLE-VALUE`)
	atd.Type()
	atd.isDefinition()
	_ = atd.String()
	atd.mutexBooleanString()

	var ls LDAPSyntax
	_ = ls.String()
	ls.OID()
	ls.isDefinition()
	ls.Type()
	ls.Valid()

	var oc ObjectClass
	_ = oc.String()
	oc.isDefinition()
	oc.OID()
	oc.Type()
	oc.Valid()

	var mr MatchingRule
	_ = mr.String()
	mr.isDefinition()
	mr.OID()
	mr.Type()
	mr.Valid()

	var mu MatchingRuleUse
	_ = mu.String()
	mu.isDefinition()
	mu.OID()
	mu.Type()
	mu.Valid()

	var dc DITContentRule
	_ = dc.String()
	dc.isDefinition()
	dc.OID()
	dc.Type()
	dc.Valid()

	var nf NameForm
	_ = nf.String()
	nf.isDefinition()
	nf.OID()
	nf.Type()
	nf.Valid()

	var ds DITStructureRule
	_ = ds.String()
	ds.isDefinition()
	ds.OID()
	ds.Type()
	ds.Valid()

	_ = stringExtensions(map[int]Extension{
		1: {XString: `X-STRING1`, Values: []string{`VALUE1`}},
		3: {XString: `X-STRING2`, Values: []string{`VALUE1`}},
	})

	tkz := newSchemaTokenizer(`(1.2.3.4 NAME 'fake')`)
	tkz.pos = 1000
	tkz.next()

	_ = parseClassKind(`0`)
	_ = parseClassKind(`1`)
	_ = parseClassKind(`2`)
	_ = parseClassKind(`3`)
	_ = stringClassKind(0)
	_ = stringClassKind(1)
	_ = stringClassKind(2)
	_ = stringClassKind(3)

	_, _ = marshalLDAPSyntax(`( 1.2.3.4
		DESC 'info'
		E-STRING 'BOGUS' )`)
	_, _ = marshalMatchingRule(`( 1.2.3.4
		NAME 'matchingrule'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = marshalAttributeType(`( 1.2.3.4
		NAME 'attribute'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = marshalObjectClass(`( 1.2.3.4
		NAME 'class'
		DESC 'info'
		OBSOLETE
		SUP top
		STRUCTURAL
		MUST c
		E-STRING 'BOGUS' )`)
	_, _ = marshalDITContentRule(`( 1.2.3.4
		NAME 'crule'
		DESC 'info'
		OBSOLETE
		AUX auxClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = marshalNameForm(`( 1.2.3.4
		NAME 'form'
		DESC 'info'
		OBSOLETE
		OC structuralClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = marshalDITStructureRule(`( 1
		NAME 'srule'
		DESC 'info'
		OBSOLETE
		FORM form
		E-STRING 'BOGUS' )`)
}

// Certain assorted definitions to be loaded into the
// "exampleSchema" instance for unit tests/examples.
// Some are make-believe, others are distinguished,
// such as "cn" or "objectClass".
var testSchemaDefinitions []string = []string{
	`attributeType: ( 2.5.4.0
	        NAME 'objectClass'
	        EQUALITY objectIdentifierMatch
	        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
	        X-ORIGIN 'RFC4512' )`,
	`attributeType: ( 2.5.18.2
		NAME 'modifyTimestamp'
	        EQUALITY generalizedTimeMatch
        	ORDERING generalizedTimeOrderingMatch
	        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
	        SINGLE-VALUE
		NO-USER-MODIFICATION
	        USAGE directoryOperation )`,
	`attributeType: ( 2.5.4.41
	        NAME 'name'
	        EQUALITY caseIgnoreMatch
	        SUBSTR caseIgnoreSubstringsMatch
	        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
	        X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.3
	        NAME ( 'cn' 'commonName' )
	        DESC 'RFC4519: common name(s) for which the entity is known by'
	        SUP name
	        X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.13
                NAME 'description'
                EQUALITY caseIgnoreMatch
                SUBSTR caseIgnoreSubstringsMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
                X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.7
                NAME ( 'l' 'localityName' )
                SUP name
                X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.11
                NAME ( 'ou' 'organizationalUnitName' )
                SUP name
                X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.49
                NAME 'distinguishedName'
                EQUALITY distinguishedNameMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
                X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.4.34
                NAME 'seeAlso'
                SUP distinguishedName
                X-ORIGIN 'RFC4519' )`,
	`attributeType: ( 2.5.18.6
		NAME 'subtreeSpecification'
           	SYNTAX 1.3.6.1.4.1.1466.115.121.1.45
           	SINGLE-VALUE
           	USAGE directoryOperation
		X-ORIGIN 'RFC3672' )`,
	`objectClass: ( 2.5.6.0
	        NAME 'top'
	        ABSTRACT
	        MUST objectClass
	        X-ORIGIN 'RFC4512' )`,
	`objectClass: ( 2.5.6.11
	        NAME 'applicationProcess'
	        SUP top
	        STRUCTURAL
	        MUST cn
	        MAY ( description
	            $ l
	            $ ou
	            $ seeAlso )
	        X-ORIGIN 'RFC4519' )`,
	`objectClass: ( 2.5.17.0
		NAME 'subentry'
           	SUP top
		STRUCTURAL
           	MUST ( cn
		     $ subtreeSpecification )
		X-ORIGIN 'RFC3672' )`,
	`( 1.3.6.1.4.1.56521.999.1234
                NAME 'applicationProcessNameForm'
                OC applicationProcess
                MUST cn
                X-ORIGIN 'FAKE' )`,
	`( 1
		NAME 'applicationProcessStructure'
		FORM applicationProcessNameForm )`,
	`( 2
		NAME 'substructureRule'
		FORM applicationProcessNameForm
		SUP 1 )`,
}

var fileBytes []byte = []byte(`
/*
Begin attributeTypes

Derived from RFC 4512, 4519 and 4524.
*/
attributeType: ( 2.5.4.1 NAME 'aliasedObjectName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE )
attributeType: ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeType: ( 2.5.18.3 NAME 'creatorsName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.18.1 NAME 'createTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.18.4 NAME 'modifiersName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.18.2 NAME 'modifyTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.21.9 NAME 'structuralObjectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.21.10 NAME 'governingStructureRule'
        EQUALITY integerMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.18.10 NAME 'subschemaSubentry'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
attributeType: ( 2.5.21.6 NAME 'objectClasses'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.37
        USAGE directoryOperation )
attributeType: ( 2.5.21.5 NAME 'attributeTypes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.3
        USAGE directoryOperation )
attributeType: ( 2.5.21.4 NAME 'matchingRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.30
        USAGE directoryOperation )
attributeType: ( 2.5.21.8 NAME 'matchingRuleUse'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.31
        USAGE directoryOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.54
        USAGE directoryOperation )
attributeType: ( 2.5.21.2 NAME 'dITContentRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.16
        USAGE directoryOperation )
attributeType: ( 2.5.21.1 NAME 'dITStructureRules'
        EQUALITY integerFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.17
        USAGE directoryOperation )
attributeType: ( 2.5.21.7 NAME 'nameForms'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.35
        USAGE directoryOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
        USAGE dSAOperation )
attributeType: ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
        USAGE dSAOperation )
attributeType: ( 2.5.4.15 NAME 'businessCategory'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.41 NAME 'name'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.6 NAME 'c'
        SUP name
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.11
        SINGLE-VALUE )
attributeType: ( 2.5.4.3
        NAME ( 'cn' 'commonName' )
        DESC 'RFC4519: common name(s) for which the entity is known by'
        SUP name )
attributeType: ( 0.9.2342.19200300.100.1.25 NAME 'dc'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
        SINGLE-VALUE )
attributeType: ( 2.5.4.13 NAME 'description'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.27 NAME 'destinationIndicator'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
attributeType: ( 2.5.4.49 NAME 'distinguishedName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeType: ( 2.5.4.46 NAME 'dnQualifier'
        EQUALITY caseIgnoreMatch
        ORDERING caseIgnoreOrderingMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
attributeType: ( 2.5.4.47 NAME 'enhancedSearchGuide'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
attributeType: ( 2.5.4.23 NAME 'facsimileTelephoneNumber'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
attributeType: ( 2.5.4.44 NAME 'generationQualifier'
        SUP name )
attributeType: ( 2.5.4.42 NAME 'givenName'
        SUP name )
attributeType: ( 2.5.4.51 NAME 'houseIdentifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.43 NAME 'initials' SUP name )
attributeType: ( 2.5.4.25 NAME 'internationalISDNNumber'
        EQUALITY numericStringMatch
        SUBSTR numericStringSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
attributeType: ( 2.5.4.7
        NAME ( 'l' 'localityName' )
        SUP name )
attributeType: ( 2.5.4.31 NAME 'member' SUP distinguishedName )
attributeType: ( 2.5.4.10 NAME 'o' SUP name )
attributeType: ( 2.5.4.11
        NAME ( 'ou' 'organizationalUnitName' )
        SUP name )
attributeType: ( 2.5.4.32 NAME 'owner' SUP distinguishedName )
attributeType: ( 2.5.4.19 NAME 'physicalDeliveryOfficeName'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.16 NAME 'postalAddress'
        EQUALITY caseIgnoreListMatch
        SUBSTR caseIgnoreListSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeType: ( 2.5.4.17 NAME 'postalCode'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.18 NAME 'postOfficeBox'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.28 NAME 'preferredDeliveryMethod'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.14
        SINGLE-VALUE )
attributeType: ( 2.5.4.26 NAME 'registeredAddress'
        SUP postalAddress
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeType: ( 2.5.4.33 NAME 'roleOccupant'
        SUP distinguishedName )
attributeType: ( 2.5.4.14 NAME 'searchGuide'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )
attributeType: ( 2.5.4.34 NAME 'seeAlso'
        SUP distinguishedName )
attributeType: ( 2.5.4.5 NAME 'serialNumber'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
attributeType: ( 2.5.4.4 NAME 'sn' SUP name )
attributeType: ( 2.5.4.8 NAME 'st' SUP name )
attributeType: ( 2.5.4.9 NAME 'street'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.20 NAME 'telephoneNumber'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeType: ( 2.5.4.22 NAME 'teletexTerminalIdentifier'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )
attributeType: ( 2.5.4.21 NAME 'telexNumber'
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
attributeType: ( 2.5.4.12 NAME 'title' SUP name )
attributeType: ( 0.9.2342.19200300.100.1.1 NAME 'uid'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 2.5.4.50 NAME 'uniqueMember'
        EQUALITY uniqueMemberMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
attributeType: ( 2.5.4.35 NAME 'userPassword'
        EQUALITY octetStringMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributeType: ( 2.5.4.24 NAME 'x121Address'
        EQUALITY numericStringMatch
        SUBSTR numericStringSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
attributeType: ( 2.5.4.45 NAME 'x500UniqueIdentifier'
        EQUALITY bitStringMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
attributeType: ( 0.9.2342.19200300.100.1.37 NAME 'associatedDomain'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeType: ( 0.9.2342.19200300.100.1.38 NAME 'associatedName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeType: ( 0.9.2342.19200300.100.1.48 NAME 'buildingName'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.43 NAME 'co'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 0.9.2342.19200300.100.1.14 NAME 'documentAuthor'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeType: ( 0.9.2342.19200300.100.1.11 NAME 'documentIdentifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.15 NAME 'documentLocation'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.56 NAME 'documentPublisher'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeType: ( 0.9.2342.19200300.100.1.12 NAME 'documentTitle'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.13 NAME 'documentVersion'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.5 NAME 'drink'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.20 NAME 'homePhone'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeType: ( 0.9.2342.19200300.100.1.39 NAME 'homePostalAddress'
        EQUALITY caseIgnoreListMatch
        SUBSTR caseIgnoreListSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeType: ( 0.9.2342.19200300.100.1.9 NAME 'host'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.4 NAME 'info'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{2048} )
attributeType: ( 0.9.2342.19200300.100.1.3 NAME 'mail'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )
attributeType: ( 0.9.2342.19200300.100.1.10 NAME 'manager'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeType: ( 0.9.2342.19200300.100.1.41 NAME 'mobile'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeType: ( 0.9.2342.19200300.100.1.45 NAME 'organizationalStatus'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.42 NAME 'pager'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeType: ( 0.9.2342.19200300.100.1.40 NAME 'personalTitle'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.6 NAME 'roomNumber'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.21 NAME 'secretary'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeType: ( 0.9.2342.19200300.100.1.44 NAME 'uniqueIdentifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 0.9.2342.19200300.100.1.8 NAME 'userClass'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeType: ( 2.5.18.5 NAME 'administrativeRole'
        EQUALITY objectIdentifierMatch
        USAGE directoryOperation
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeType: ( 2.5.18.6 NAME 'subtreeSpecification'
        SINGLE-VALUE
        USAGE directoryOperation
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 )

/*
Begin objectClasses.

Derived from RFCs 4512, 4519 and 4524.
*/
objectClass: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )
objectClass: ( 2.5.6.1 NAME 'alias'
        SUP top STRUCTURAL
        MUST aliasedObjectName )
objectClass: ( 2.5.20.1 NAME 'subschema' AUXILIARY
        MAY ( dITStructureRules $ nameForms $ dITContentRules $
          objectClasses $ attributeTypes $ matchingRules $
          matchingRuleUse ) )
objectClass: ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject'
        SUP top AUXILIARY )
objectClass: ( 2.5.6.11 NAME 'applicationProcess'
        SUP top
        STRUCTURAL
        MUST cn
        MAY ( seeAlso $
              ou $
              l $
              description ) )
objectClass: ( 2.5.6.2 NAME 'country'
        SUP top
        STRUCTURAL
        MUST c
        MAY ( searchGuide $
              description ) )
objectClass: ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
        SUP top
        AUXILIARY
        MUST dc )
objectClass: ( 2.5.6.14 NAME 'device'
        SUP top
        STRUCTURAL
        MUST cn
        MAY ( serialNumber $
              seeAlso $
              owner $
              ou $
              o $
              l $
              description ) )
objectClass: ( 2.5.6.9 NAME 'groupOfNames'
        SUP top
        STRUCTURAL
        MUST ( member $
              cn )
        MAY ( businessCategory $
              seeAlso $
              owner $
              ou $
              o $
              description ) )
objectClass: ( 2.5.6.17 NAME 'groupOfUniqueNames'
        SUP top
        STRUCTURAL
        MUST ( uniqueMember $
              cn )
        MAY ( businessCategory $
              seeAlso $
              owner $
              ou $
              o $
              description ) )
objectClass: ( 2.5.6.3 NAME 'locality'
        SUP top
        STRUCTURAL
        MAY ( street $
              seeAlso $
              searchGuide $
              st $
              l $
              description ) )
objectClass: ( 2.5.6.4 NAME 'organization'
        SUP top
        STRUCTURAL
        MUST o
        MAY ( userPassword $ searchGuide $ seeAlso $
              businessCategory $ x121Address $ registeredAddress $
              destinationIndicator $ preferredDeliveryMethod $
              telexNumber $ teletexTerminalIdentifier $
              telephoneNumber $ internationalISDNNumber $
              facsimileTelephoneNumber $ street $ postOfficeBox $
              postalCode $ postalAddress $ physicalDeliveryOfficeName $
              st $ l $ description ) )
objectClass: ( 2.5.6.6 NAME 'person'
        SUP top
        STRUCTURAL
        MUST ( sn $
              cn )
        MAY ( userPassword $
              telephoneNumber $
              seeAlso $ description ) )
objectClass: ( 2.5.6.7 NAME 'organizationalPerson'
        SUP person
        STRUCTURAL
        MAY ( title $ x121Address $ registeredAddress $
              destinationIndicator $ preferredDeliveryMethod $
              telexNumber $ teletexTerminalIdentifier $
              telephoneNumber $ internationalISDNNumber $
              facsimileTelephoneNumber $ street $ postOfficeBox $
              postalCode $ postalAddress $ physicalDeliveryOfficeName $
              ou $ st $ l ) )
objectClass: ( 2.5.6.8 NAME 'organizationalRole'
        SUP top
        STRUCTURAL
        MUST cn
        MAY ( x121Address $ registeredAddress $ destinationIndicator $
              preferredDeliveryMethod $ telexNumber $
              teletexTerminalIdentifier $ telephoneNumber $
              internationalISDNNumber $ facsimileTelephoneNumber $
              seeAlso $ roleOccupant $ preferredDeliveryMethod $
              street $ postOfficeBox $ postalCode $ postalAddress $
              physicalDeliveryOfficeName $ ou $ st $ l $
              description ) )
objectClass: ( 2.5.6.5 NAME 'organizationalUnit'
        SUP top
        STRUCTURAL
        MUST ou
        MAY ( businessCategory $ description $ destinationIndicator $
              facsimileTelephoneNumber $ internationalISDNNumber $ l $
              physicalDeliveryOfficeName $ postalAddress $ postalCode $
              postOfficeBox $ preferredDeliveryMethod $
              registeredAddress $ searchGuide $ seeAlso $ st $ street $
              telephoneNumber $ teletexTerminalIdentifier $
              telexNumber $ userPassword $ x121Address ) )
objectClass: ( 2.5.6.10 NAME 'residentialPerson'
        SUP person
        STRUCTURAL
        MUST l
        MAY ( businessCategory $ x121Address $ registeredAddress $
              destinationIndicator $ preferredDeliveryMethod $
              telexNumber $ teletexTerminalIdentifier $
              telephoneNumber $ internationalISDNNumber $
              facsimileTelephoneNumber $ preferredDeliveryMethod $
              street $ postOfficeBox $ postalCode $ postalAddress $
              physicalDeliveryOfficeName $ st $ l ) )
objectClass: ( 1.3.6.1.1.3.1 NAME 'uidObject'
        SUP top
        AUXILIARY
        MUST uid )
objectClass: ( 0.9.2342.19200300.100.4.5 NAME 'account'
        SUP top STRUCTURAL
        MUST uid
        MAY ( description $ seeAlso $ l $ o $ ou $ host ) )
objectClass: ( 0.9.2342.19200300.100.4.6 NAME 'document'
        SUP top STRUCTURAL
        MUST documentIdentifier
        MAY ( cn $ description $ seeAlso $ l $ o $ ou $
          documentTitle $ documentVersion $ documentAuthor $
          documentLocation $ documentPublisher ) )
objectClass: ( 0.9.2342.19200300.100.4.9 NAME 'documentSeries'
        SUP top STRUCTURAL
        MUST cn
        MAY ( description $ l $ o $ ou $ seeAlso $
          telephonenumber ) )
objectClass: ( 0.9.2342.19200300.100.4.13 NAME 'domain'
        SUP top STRUCTURAL
        MUST dc
        MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
          x121Address $ registeredAddress $ destinationIndicator $
          preferredDeliveryMethod $ telexNumber $
          teletexTerminalIdentifier $ telephoneNumber $
          internationaliSDNNumber $ facsimileTelephoneNumber $ street $
          postOfficeBox $ postalCode $ postalAddress $
          physicalDeliveryOfficeName $ st $ l $ description $ o $
          associatedName ) )
objectClass: ( 0.9.2342.19200300.100.4.17 NAME 'domainRelatedObject'
        SUP top AUXILIARY
        MUST associatedDomain )
objectClass: ( 0.9.2342.19200300.100.4.18 NAME 'friendlyCountry'
        SUP country STRUCTURAL
        MUST co )
objectClass: ( 0.9.2342.19200300.100.4.14 NAME 'rFC822localPart'
        SUP domain STRUCTURAL
        MAY ( cn $ description $ destinationIndicator $
          facsimileTelephoneNumber $ internationaliSDNNumber $
          physicalDeliveryOfficeName $ postalAddress $ postalCode $
          postOfficeBox $ preferredDeliveryMethod $ registeredAddress $
          seeAlso $ sn $ street $ telephoneNumber $
          teletexTerminalIdentifier $ telexNumber $ x121Address ) )
objectClass: ( 0.9.2342.19200300.100.4.7 NAME 'room'
        SUP top STRUCTURAL
        MUST cn
        MAY ( roomNumber $ description $ seeAlso $ telephoneNumber ) )
objectClass: ( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject'
        SUP top AUXILIARY
        MUST userPassword )
objectClass: ( 2.5.17.0
        NAME 'subentry'
        SUP top
        STRUCTURAL
        MUST ( cn
             $ subtreeSpecification )
        X-ORIGIN 'RFC3672' )
nameForm: ( 1.3.6.1.4.1.56521.999.1234
        NAME 'applicationProcessNameForm'
        OC applicationProcess
        MUST cn
        X-ORIGIN 'FAKE' )
dITStructureRule: ( 1
        NAME 'applicationProcessStructure'
        FORM applicationProcessNameForm )
dITStructureRule: ( 2
        NAME 'substructureRule'
        FORM applicationProcessNameForm
        SUP 1 )
`)

// for unit tests and pkgsite examples.
var exampleSchema *SubschemaSubentry

func init() {
	var r RFC4512
	exampleSchema = r.SubschemaSubentry()
	if err := exampleSchema.ReadBytes(fileBytes); err != nil {
		panic(err)
	}
}
