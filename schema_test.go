package dirsyn

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func ExampleLDAPSyntaxes_IsZero() {
	var defs LDAPSyntaxes
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleMatchingRules_IsZero() {
	var defs MatchingRules
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleAttributeTypes_IsZero() {
	var defs AttributeTypes
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleMatchingRuleUses_IsZero() {
	var defs MatchingRuleUses
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleObjectClasses_IsZero() {
	var defs ObjectClasses
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleDITContentRules_IsZero() {
	var defs DITContentRules
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleNameForms_IsZero() {
	var defs NameForms
	fmt.Println(defs.IsZero())
	// Output: true
}

func ExampleDITStructureRules_IsZero() {
	var defs DITStructureRules
	fmt.Println(defs.IsZero())
	// Output: true
}

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

func ExampleLDAPSyntax_XOrigin() {
	def, idx := exampleSchema.LDAPSyntaxes.Get(`nisNetgroupTripleSyntax`)
	if idx == -1 {
		fmt.Println("Syntax not found")
		return
	}

	fmt.Println(def.XOrigin())
	// Output: [RFC2307]
}

func ExampleMatchingRule_XOrigin() {
	def, idx := exampleSchema.MatchingRules.Get(`objectIdentifierMatch`)
	if idx == -1 {
		fmt.Println("Matching rule not found")
		return
	}

	fmt.Println(def.XOrigin())
	// Output: [RFC4517]
}

func ExampleSubschemaSubentry_UnregisterAttributeType() {
	def := `( 1.3.6.1.4.1.56521.999.9.5
                NAME 'fakeAttribute'
                SUP name )`
	err := exampleSchema.UnregisterAttributeType(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleSubschemaSubentry_UnregisterObjectClass() {
	def := `( 1.3.6.1.4.1.56521.999.10.1
                NAME 'testClass'
                DESC 'a fake class'
                MUST cn
                MAY ( fakeAttribute $ otherAttribute ) )`
	err := exampleSchema.UnregisterObjectClass(def)
	fmt.Println(err == nil) // should succeed (no dependents)
	// Output: true
}

func ExampleSubschemaSubentry_Unregister_attributeType() {
	// First lookup the type in question and obtain
	// the proper instance.
	def, idx := exampleSchema.AttributeType("fakeAttribute")
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the type instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should succeed (no dependents)
	// Output: true
}

func ExampleSubschemaSubentry_Unregister_dITContentRule() {
	// First lookup the rule in question and obtain
	// the proper instance.
	_, idx := exampleSchema.DITContentRule("nonexistentRule")
	fmt.Println(idx == -1) // should fail due to it not existing.
	// Output: true
}

func ExampleSubschemaSubentry_Unregister_objectClass() {
	// First lookup the class in question and obtain
	// the proper instance.
	def, idx := exampleSchema.ObjectClass("top")
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the class instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleSubschemaSubentry_Unregister_lDAPSyntax() {
	// First lookup the syntax in question and obtain
	// the proper instance.
	booleanSyntax := "1.3.6.1.4.1.1466.115.121.1.7"
	def, idx := exampleSchema.LDAPSyntax(booleanSyntax)
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the syntax instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleSubschemaSubentry_Unregister_unusedLDAPSyntax() {
	// First lookup the syntax in question and obtain
	// the proper instance.
	bootParam := "bootParameterSyntax"
	def, idx := exampleSchema.LDAPSyntax(bootParam)
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the syntax instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should succeed
	// Output: true
}

func ExampleSubschemaSubentry_Unregister_matchingRule() {
	// First lookup the rule in question and obtain
	// the proper instance.
	def, idx := exampleSchema.MatchingRule("caseIgnoreMatch")
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the rule instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleSubschemaSubentry_Unregister_nameForm() {
	// First lookup the form in question and obtain
	// the proper instance.
	nf := "applicationProcessNameForm"
	def, idx := exampleSchema.NameForm(nf)
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the form instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleSubschemaSubentry_Unregister_dITStructureRule() {
	// First lookup the rule in question and obtain
	// the proper instance.
	def, idx := exampleSchema.DITStructureRule("1")
	if idx == -1 {
		fmt.Printf("Not found!")
		return
	}

	// Now we use the rule instance to call Unregister.
	err := exampleSchema.Unregister(def)
	fmt.Println(err == nil) // should fail due to dependencies
	// Output: false
}

func ExampleAttributeType_EffectiveSyntax() {
	title, idx := exampleSchema.AttributeTypes.Get(`title`)
	if idx == -1 {
		fmt.Println("Attribute not found!")
		return
	}

	// NOTE: The "title" attributeType definition
	// is a subtype of the "name" attributeType.

	syntax := title.EffectiveSyntax()
	fmt.Println(syntax.Identifier())
	// Output: 1.3.6.1.4.1.1466.115.121.1.15

}

func ExampleAttributeType_EffectiveEquality() {
	title, idx := exampleSchema.AttributeTypes.Get(`title`)
	if idx == -1 {
		fmt.Println("Attribute not found!")
		return
	}

	// NOTE: The "title" attributeType definition
	// is a subtype of the "name" attributeType.

	equality := title.EffectiveEquality()
	fmt.Println(equality.Identifier())
	// Output: caseIgnoreMatch

}

func ExampleAttributeType_EffectiveSubstring() {
	title, idx := exampleSchema.AttributeTypes.Get(`title`)
	if idx == -1 {
		fmt.Println("Attribute not found!")
		return
	}

	// NOTE: The "title" attributeType definition
	// is a subtype of the "name" attributeType.

	substr := title.EffectiveSubstring()
	fmt.Println(substr.Identifier())
	// Output: caseIgnoreSubstringsMatch

}

func ExampleAttributeType_EffectiveOrdering() {
	dnq, idx := exampleSchema.AttributeTypes.Get(`dnQualifier`)
	if idx == -1 {
		fmt.Println("Attribute not found!")
		return
	}

	ordering := dnq.EffectiveOrdering()
	fmt.Println(ordering.Identifier())
	// Output: caseIgnoreOrderingMatch
}

func ExampleSubschemaSubentry_Push_lDAPSyntax() {
	exampleSchema.Push(&LDAPSyntax{
		NumericOID:  "1.3.6.1.4.1.56521.999.10.11",
		Description: "Fake syntax",
	})

	fmt.Printf("Found definition at index #%d\n",
		exampleSchema.LDAPSyntaxes.Contains("1.3.6.1.4.1.56521.999.10.11"))
	// Output: Found definition at index #66
}

func ExampleSubschemaSubentry_Push_matchingRule() {
	exampleSchema.Push(&MatchingRule{
		NumericOID:  "1.3.6.1.4.1.56521.999.20.11",
		Name:        []string{`fakeRule`},
		Description: "Fake rule",
		Syntax:      "1.3.6.1.4.1.56521.999.10.11",
	})

	fmt.Printf("Found definition at index #%d\n",
		exampleSchema.MatchingRules.Contains("1.3.6.1.4.1.56521.999.20.11"))
	// Output: Found definition at index #44
}

func ExampleSubschemaSubentry_Push_attributeType() {
	exampleSchema.Push(&AttributeType{
		NumericOID:  "1.3.6.1.4.1.56521.999.40.11",
		Name:        []string{`fakeType`},
		Description: "Fake type",
		SuperType:   "description",
	})

	fmt.Printf("Found definition at index #%d\n",
		exampleSchema.AttributeTypes.Contains("1.3.6.1.4.1.56521.999.40.11"))
	// Output: Found definition at index #96
}

func ExampleSubschemaSubentry_Push_objectClass() {
	exampleSchema.Push(&ObjectClass{
		NumericOID:   "1.3.6.1.4.1.56521.999.50.11",
		Name:         []string{`fakeClass`},
		Description:  "Fake class",
		Kind:         0,
		SuperClasses: []string{"top"},
	})

	fmt.Printf("Found definition at index #%d\n",
		exampleSchema.ObjectClasses.Contains("1.3.6.1.4.1.56521.999.50.11"))
	// Output: Found definition at index #28
}

func ExampleSubschemaSubentry_Push_dITContentRule() {
	exampleSchema.Push(&DITContentRule{
		NumericOID:  "1.3.6.1.4.1.56521.999.50.11",
		Name:        []string{`fakeRule`},
		Description: "Fake rule",
		Not:         []string{"audio"},
	})

	fmt.Printf("Found definition at index #%d\n",
		exampleSchema.DITContentRules.Contains("1.3.6.1.4.1.56521.999.50.11"))
	// Output: Found definition at index #1
}

/*
This example demonstrates a convenient means of counting
each [SchemaDefinition] by category. The return type (an
instance of [9]uint) is of the following structure:

	 LDAPSyntaxes
	 |  MatchingRules
	 |  |  AttributeTypes
	 |  |  |  MatchingRuleUses
	 |  |  |  |
	 |  |  |  |
	 |  |  |  |
	[67 44 96 44 29 0 1 2 283]
	             |  | | | |
	             |  | | | Grand Total
	             |  | | DITStructureRules
	             |  | NameForms
	             |  DITContentRules
	             ObjectClasses
*/
func ExampleSubschemaSubentry_Counters() {
	fmt.Println(exampleSchema.Counters())
	// Output: [67 45 97 44 29 2 1 2 287]
}

func ExampleAttributeType_SuperChain() {
	types := exampleSchema.AttributeTypes
	child, _ := types.Get(`cn`)
	supers := child.SuperChain()
	fmt.Println(supers)
	// Output: attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
}

func ExampleObjectClass_SuperClassOf() {
	classes := exampleSchema.ObjectClasses
	top, idx := classes.Get(`top`) // 2.5.6.0
	if idx == -1 {
		// not found
		return
	}

	fmt.Println(top.SuperClassOf(`subentry`))
	// Output: true
}

func ExampleObjectClass_SuperChain() {
	child, _ := exampleSchema.ObjectClass(`subentry`)
	fmt.Println(child.SuperChain())
	// Output:
	// objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )
	// objectClasses: ( 2.5.17.0 NAME 'subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) X-ORIGIN 'RFC3672' )
}

func ExampleObjectClass_AllMust() {
	child, _ := exampleSchema.ObjectClass(`subentry`)
	fmt.Println(child.AllMust())
	// Output:
	// attributeTypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
	// attributeTypes: ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )
	// attributeTypes: ( 2.5.18.6 NAME 'subtreeSpecification' SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 SINGLE-VALUE USAGE directoryOperation )
}

func ExampleObjectClass_AllMay() {
	child, _ := exampleSchema.ObjectClass(`applicationProcess`)
	fmt.Println(child.AllMay())
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

func ExampleAttributeTypes_Table() {
	table := exampleSchema.AttributeTypes.Table()
	fmt.Printf("Table contains %d indices", len(table))
	// Output: Table contains 98 indices
}

func ExampleDITStructureRule_NamedObjectClass() {
	dsr, idx := exampleSchema.DITStructureRules.Get(`1`)
	if idx == -1 {
		fmt.Println("Structure Rule #1 not found")
		return
	}

	fmt.Println(dsr.NamedObjectClass().Identifier())
	// Output: applicationProcess
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

func ExampleDITStructureRule_SuperiorStructureRules() {
	dsr, idx := exampleSchema.DITStructureRules.Get(`1`)
	if idx == -1 {
		fmt.Println("Structure Rule #1 not found")
		return
	}

	sups := dsr.SuperiorStructureRules()
	fmt.Printf("Rule is a root: %t", sups.Len() == 0)
	// Output: Rule is a root: true
}

func ExampleDITStructureRule_SubordinateStructureRules() {
	dsr, idx := exampleSchema.DITStructureRules.Get(`1`)
	if idx == -1 {
		fmt.Println("Structure Rule #1 not found")
		return
	}

	subs := dsr.SubordinateStructureRules()
	fmt.Printf("Number of subordinate rules: %d", subs.Len())
	// Output: Number of subordinate rules: 2
}

func TestSubschemaSubentry_codecov(t *testing.T) {

	_ = exampleSchema.ReadFile("/tmp/fake.file")
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
	_ = exampleSchema.LDAPSyntaxes.Table()
	_ = exampleSchema.MatchingRules.Table()
	_ = exampleSchema.AttributeTypes.Table()
	_ = exampleSchema.MatchingRuleUses.Table()
	_ = exampleSchema.ObjectClasses.Table()
	_ = exampleSchema.DITContentRules.Table()
	_ = exampleSchema.NameForms.Table()
	_ = exampleSchema.DITStructureRules.Table()

	_ = exampleSchema.LDAPSyntaxByIndex(0)
	_ = exampleSchema.MatchingRuleByIndex(0)
	_ = exampleSchema.AttributeTypeByIndex(0)
	_ = exampleSchema.MatchingRuleUseByIndex(0)
	_ = exampleSchema.ObjectClassByIndex(0)
	_ = exampleSchema.DITContentRuleByIndex(0)
	_ = exampleSchema.NameFormByIndex(0)
	_ = exampleSchema.DITStructureRuleByIndex(0)
	_ = exampleSchema.Unregister(&LDAPSyntax{})
	_ = exampleSchema.UnregisterLDAPSyntax(rune(10))
	_ = exampleSchema.Unregister(&MatchingRule{})
	_ = exampleSchema.UnregisterMatchingRule(rune(10))
	_ = exampleSchema.Unregister(&AttributeType{})
	_ = exampleSchema.UnregisterAttributeType(rune(10))
	_ = exampleSchema.Unregister(&ObjectClass{})
	_ = exampleSchema.UnregisterObjectClass(rune(10))
	_ = exampleSchema.Unregister(&DITContentRule{})
	_ = exampleSchema.UnregisterDITContentRule(rune(10))
	_ = exampleSchema.Unregister(&NameForm{})
	_ = exampleSchema.UnregisterNameForm(rune(10))
	_ = exampleSchema.Unregister(&DITStructureRule{})
	_ = exampleSchema.UnregisterDITStructureRule(rune(10))
	_ = exampleSchema.dITContentRuleDepScan(&DITContentRule{})

	_ = exampleSchema.matchingRuleDepScan(&MatchingRule{
		NumericOID: `1.2.3.4`,
		Name:       []string{"fakeRule"},
	})

	ruleu := MatchingRuleUse{
		NumericOID: `1.2.3.4`,
	}
	ruleu.Identifier()

	ruleu.Name = []string{"someMatchingRule"}
	ruleu.Identifier()

	marshalLDAPSyntax([]byte(`bogus`))
	marshalMatchingRule([]byte(`bogus`))
	marshalDITContentRule([]byte(`bogus`))
	marshalDITContentRule([]byte(`( 2.5.6.5 NAME 'fakeContentRule' MAY cn )`))
	exampleSchema.registerSchemaByCase([][]byte{[]byte("ldapsyntax")})
	exampleSchema.registerSchemaByCase([][]byte{[]byte("matchingrule")})
	exampleSchema.registerSchemaByCase([][]byte{[]byte("ditcontentrule")})

	exampleSchema.MatchingRuleUses.Contains(exampleSchema.MatchingRuleUses.defs[0].Identifier())
	errorPrimerFailed(1, 1)

	dcrs := DITContentRules{
		defs: []*DITContentRule{{}},
	}
	_ = dcrs.String()

	lDAPSyntaxDescription(`111111111111111111111111111`)
	matchingRuleDescription(`111111111111111111111111111`)
	matchingRuleUseDescription(`111111111111111111111111111`)
	attributeTypeDescription(`111111111111111111111111111`)
	objectClassDescription(`111111111111111111111111111`)
	dITContentRuleDescription(`111111111111111111111111111`)
	nameFormDescription(`111111111111111111111111111`)
	dITStructureRuleDescription(`111111111111111111111111111`)

	dcr := DITContentRule{
		Name: []string{"name"},
		Aux:  []string{"___"},
		Must: []string{"___"},
		May:  []string{"___"},
		Not:  []string{"___"},
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}

	dcr.Valid()
	dcr.IsZero()
	dcr.Identifier()
	dcr = DITContentRule{
		NumericOID: "2.5.6.5",
		Must:       []string{"cn"},
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}
	dcrs.defs = append(dcrs.defs, &dcr)
	_ = dcrs.Table()
	_ = dcr.String()
	dcr.XOrigin()

	marshalMatchingRuleUse(rune(33))
	marshalMatchingRuleUse([]byte(`1111`))
	marshalNameForm(`( 1.2.3.4 NAME 'form' OC account MUST cn MAY l )`)
	marshalMatchingRuleUse(`( 1.2.3.4 NAME 'rule' DESC 'example' OBSOLETE APPLIES cn X-ORIGIN 'nowhere' )`)
	dsr := DITStructureRule{
		SuperRules: []string{"-1"},
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}
	dsr.Valid()
	dsr.IsZero()
	dsr.XOrigin()

	at, _ := exampleSchema.AttributeTypes.Get("cn")
	at.EffectiveOrdering()
	at.SuperiorType()
	at.IsZero()
	at.XOrigin()
	at, _ = exampleSchema.AttributeTypes.Get("name")
	at.SubordinateTypes()

	typ := &AttributeType{
		NumericOID: `2.5.4.1000`,
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}
	typ.XOrigin()

	_ = exampleSchema.attributeTypeDepScan(nil)
	_ = exampleSchema.attributeTypeDepScan(at)
	_ = exampleSchema.registerSchemaByCase([][]byte{[]byte(`bogus`)})

	class := &ObjectClass{
		NumericOID: `2.5.6.5`,
		SuperClasses: []string{
			`___`,
		},
		Must: []string{
			`_____`,
		},
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}
	class.Valid()
	class.IsZero()
	class.XOrigin()
	class.SuperiorClasses()
	class.SubordinateClasses()
	class, _ = exampleSchema.ObjectClasses.Get("organizationalPerson")
	class.AllMay()
	class.SuperiorClasses()
	class.SuperClassOf(nil)
	class.SuperClassOf(`bogus`)
	class.SuperClassOf(`subentry`)
	exampleSchema.ObjectClasses.defs = append(exampleSchema.ObjectClasses.defs, exampleSchema.ObjectClasses.defs[0])
	exampleSchema.ObjectClasses.Contains(exampleSchema.ObjectClasses.defs[0].Identifier())
	exampleSchema.ObjectClasses.truncate(exampleSchema.ObjectClasses.Len() - 1)

	form := &NameForm{
		NumericOID: `2.5.6.5`,
		Must:       []string{`____`},
		May:        []string{`____`},
		Extensions: map[int]Extension{
			0: {XString: "X-ORIGIN", Values: []string{"NOWHERE"}},
		},
	}
	form.Valid()
	form.IsZero()
	form.XOrigin()

	exampleSchema.NameForms.defs = append(exampleSchema.NameForms.defs, exampleSchema.NameForms.defs[0])
	exampleSchema.NameForms.Contains(exampleSchema.NameForms.defs[0].Identifier())
	exampleSchema.NameForms.unregister(exampleSchema.NameForms.Len()-1, form, func(*NameForm) error { return nil })

	var def SchemaDefinition
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

	def, _ = exampleSchema.NameForm(`applicationProcessNameForm`)
	_ = def.XOrigin()

	def, _ = exampleSchema.DITStructureRule(`substructureRule`)
	_ = def.XOrigin()
	def.(*DITStructureRule).SuperiorStructureRules()

	_ = exampleSchema.RegisterDITStructureRule(`( 3
		NAME 'substructureRule'
		FORM applicationProcessNameForm
		SUP 40 )`)

	bogusDS := &DITStructureRule{
		RuleID: "44",
		Name:   []string{"bogusDSR"},
	}
	exampleSchema.DITStructureRules.defs = append(exampleSchema.DITStructureRules.defs, bogusDS)
	exampleSchema.DITStructureRules.Contains(exampleSchema.DITStructureRules.defs[0].Identifier())
	exampleSchema.DITStructureRules.unregister(exampleSchema.DITStructureRules.Len()-1, bogusDS, func(*DITStructureRule) error { return nil })

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

	_ = exampleSchema.DITContentRules.Type()

	stringBooleanClause(`test`, true)
	stringBooleanClause(`test`, false)

	_ = lDAPSyntaxDescription(primerSyntaxes[0])
	_ = matchingRuleDescription(primerMatchingRules[0])
	_ = matchingRuleUseDescription(`( 2.5.13.10 NAME numericStringSubstringsMatch APPLIES zz )`)
	_ = attributeTypeDescription(testSchemaDefinitions[0])
	_ = objectClassDescription(testSchemaDefinitions[4])
	//_ = dITContentRuleDescription(testSchemaDefinitions[10])
	_ = nameFormDescription(testSchemaDefinitions[12])
	//_ = dITStructureRuleDescription(testSchemaDefinitions[13])

	exampleSchema.RegisterDITContentRule(`()`)

	mrus := exampleSchema.NewMatchingRuleUses()
	mru := &MatchingRuleUse{
		NumericOID:  `2.5.13.15`,
		Description: `this is text`,
		Name:        []string{`userRule`},
		Applies:     []string{`cn`, `sn`, `blarg`},
	}
	mrus.push(mru)

	exampleSchema.unregisterMatchingRuleUsers(&AttributeType{NumericOID: `2.2.2.2`, Name: []string{"blarg"}})
	typ, _ = exampleSchema.AttributeTypes.Get(`cn`)

	mru.truncate(typ)
	mrus.truncate(0)

	_ = mrus.String()
	mrus.isDefinitions()

	lss := exampleSchema.NewLDAPSyntaxes()
	lss.isDefinitions()

	mrs := exampleSchema.NewMatchingRules()
	mrs.isDefinitions()

	ats := exampleSchema.NewAttributeTypes()
	ats.isDefinitions()

	ocs := exampleSchema.NewObjectClasses()
	ocs.isDefinitions()

	dcs := exampleSchema.NewDITContentRules()
	dcs.isDefinitions()

	nfs := exampleSchema.NewNameForms()
	nfs.isDefinitions()

	dss := exampleSchema.NewDITStructureRules()
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

	var ls *LDAPSyntax = &LDAPSyntax{}
	_ = ls.String()
	ls.OID()
	ls.isDefinition()
	ls.Type()
	ls.Valid()
	ls.IsZero()

	ls, _ = exampleSchema.LDAPSyntaxes.Get("directory string")
	exampleSchema.ldapSyntaxDepScan(ls)

	var oc ObjectClass
	_ = oc.String()
	oc.isDefinition()
	oc.OID()
	oc.Type()
	oc.Valid()

	var mr *MatchingRule = &MatchingRule{}
	_ = mr.String()
	mr.isDefinition()
	mr.OID()
	mr.Type()
	mr.Valid()
	mr.IsZero()

	mr, _ = exampleSchema.MatchingRules.Get("caseExactMatch")
	exampleSchema.matchingRuleDepScan(mr)

	bogusMR := &MatchingRule{
		NumericOID: `2.2.2.2`,
		Name:       []string{`bogusRule`},
	}
	exampleSchema.MatchingRules.defs = append(exampleSchema.MatchingRules.defs, bogusMR)
	exampleSchema.MatchingRules.Contains(exampleSchema.MatchingRules.defs[exampleSchema.MatchingRules.Len()-1].Identifier())
	exampleSchema.MatchingRules.unregister(exampleSchema.MatchingRules.Len()-1, bogusMR, func(*MatchingRule) error { return nil })

	var mu *MatchingRuleUse = &MatchingRuleUse{}
	_ = mu.String()
	mu.isDefinition()
	mu.OID()
	mu.Type()
	mu.Valid()
	mu.IsZero()

	var dc *DITContentRule = &DITContentRule{}
	_ = dc.String()
	dc.isDefinition()
	dc.OID()
	dc.Type()
	dc.Valid()

	exampleSchema.RegisterDITContentRule(`( 2.5.6.5 NAME 'fakePersonRule' DESC 'Fake person' AUX extensibleObject NOT xxxn X-ORIGIN 'NOWHERE' )`)
	exampleSchema.RegisterDITContentRule(`( 2.5.6.5 NAME 'fakePersonRule' DESC 'Fake person' AUX xxxxextensibleObject NOT cn X-ORIGIN 'NOWHERE' )`)
	exampleSchema.RegisterDITContentRule(`( 2.5.6.5 NAME 'fakePersonRule' DESC 'Fake person' AUX applicationProcess NOT cn X-ORIGIN 'NOWHERE' )`)
	exampleSchema.RegisterDITContentRule(`( 3.1.2.3 NAME 'fakePersonRule' DESC 'Fake person' AUX applicationProcess NOT cn X-ORIGIN 'NOWHERE' )`)
	dc = &DITContentRule{
		NumericOID:  "2.5.6.5",
		Name:        []string{`fakePersonRule`},
		Description: "Fake person",
		Not:         []string{"cn"},
		Aux:         []string{"extensibleObject"},
	}
	exampleSchema.Push(dc)
	exampleSchema.RegisterDITContentRule(`( 2.5.6.5 NAME 'fakePersonRule' DESC 'Fake person' AUX extensibleObject NOT cn X-ORIGIN 'NOWHERE' )`)

	exampleSchema.DITContentRules.defs = append(exampleSchema.DITContentRules.defs, exampleSchema.DITContentRules.defs[0])
	exampleSchema.DITContentRules.Contains(exampleSchema.DITContentRules.defs[0].Identifier())
	exampleSchema.DITContentRules.truncate(exampleSchema.DITContentRules.Len() - 1)

	cname, _ := exampleSchema.AttributeTypes.Get(`cn`)
	exampleSchema.attributeTypeDITContentRuleDepScan(cname)
	exampleSchema.attributeTypeNameFormDepScan(cname)
	exampleSchema.UnregisterDITContentRule(dc)

	exob, _ := exampleSchema.ObjectClasses.Get(`extensibleObject`)
	pers, _ := exampleSchema.ObjectClasses.Get(`2.5.6.5`)
	aprc, _ := exampleSchema.ObjectClasses.Get(`applicationProcess`)
	exampleSchema.objectClassDepScan(exob)
	exampleSchema.objectClassDepScan(pers)
	exampleSchema.objectClassDepScan(aprc)

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
attributeType: ( 1.3.6.1.4.1.250.1.57
	NAME 'labeledURI'
	EQUALITY caseExactMatch
	SUBSTR caseExactSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

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
        SUP ( 1 2 ) )
`)

// for unit tests and pkgsite examples.
var exampleSchema *SubschemaSubentry

func init() {
	name := "schemaInit"

	/*
		create "/<temporary_dir>/schema-dir-read-test/example.schema" and
		parse its definitions. The resulting schema
	*/
	tempDir, err := os.MkdirTemp("", "schema-dir-read-test")
	if err != nil {
		panic(fmt.Sprintf("%s failed [make tmp]: %v", name, err))
	}

	defer os.RemoveAll(tempDir)
	filePath := filepath.Join(tempDir, "example.schema")

	var file *os.File
	if file, err = os.Create(filePath); err != nil {
		panic(fmt.Sprintf("%s failed [make file]: %v", name, err))
	}

	defer file.Close()

	if _, err = file.Write(fileBytes); err != nil {
		panic(fmt.Sprintf("%s failed [read bytes]: %v", name, err))
	}

	var r RFC4512
	if exampleSchema, err = r.SubschemaSubentry(true); err != nil {
		panic(fmt.Sprintf("%s failed [schema init]: %v", name, err))
	}

	if err = exampleSchema.ReadDirectory(tempDir); err != nil {
		panic(fmt.Sprintf("%s failed [dir read]: %v", name, err))
	}

	want := 281
	if counters := exampleSchema.Counters(); int(counters[8]) != want {
		panic(fmt.Sprintf("%s failed [counter check]:\n\twant: '%d'\n\tgot:  '%d'", name, want, counters[8]))
	}
}
