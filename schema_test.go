package dirsyn

import "testing"

var testSchemaDefinitions []string = []string{
	// LDAPSyntaxDescription
	`( 1.3.6.1.4.1.56521.101.2.1.3
		DESC 'a syntax'
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// LDAPSyntaxDescription #2
	`( 1.3.6.1.4.1.56521.101.2.1.4
		DESC 'another syntax'
		X-THING (
			'this is a value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// MatchingRuleDescription
	`( 2.5.15.13
		NAME 'def'
		DESC 'a matching rule'
		SYNTAX 1.3.6.1.4.1.56521.101.2.1.1
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// AttributeTypeDescription
	`( 2.5.4.3 NAME (
			'cn'
			'commonName'
		)
		DESC 'this isn\'t a bad example'
		OBSOLETE
		SUP 2.5.4.41
		EQUALITY 2.5.13.2
		ORDERING 2.5.13.3
		SUBSTR 2.5.13.4
		SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32}
		SINGLE-VALUE
		NO-USER-MODIFICATION
		USAGE dSAOperation
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// MRU not needed
	``,

	// ObjectClassDescription
	`( 2.5.6.0
		NAME 'class'
		DESC 'an object class'
		SUP ( domain
		    $ locality
		)
		AUXILIARY
		MUST ( cn
		     $ sn
		     $ l
		     $ o
		)
		MAY description
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// DITContentRuleDescription
	`( 2.5.6.0
		NAME ( 'crule' )
		DESC 'an content rule'
		AUX ( domain
		    $ locality
		)
		MUST ( cn
		     $ sn
		     $ l
		     $ o )
		MAY description
		NOT userPassword
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// NameFormDescription
	`( 2.5.6.0
		NAME ( 'nameform' )
		DESC 'a name form'
		OC domain
		MUST ( cn
		     $ sn
		)
		MAY o
		X-THING (
			 'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE' )`,

	// DITStructureRuleDescription
	`( 2
		NAME ( 'srule' )
		DESC 'a structure rule'
		FORM nameform
		SUP (
			1
			2
		)
		X-THING (
			'this is a value'
			'this is another value'
		)
		X-ORIGIN 'NOWHERE'
		X-THINGS (
			'one'
			'two'
		))`,
}

func TestSubschemaSubentry(t *testing.T) {
	var schema SubschemaSubentry

	var def0a, def0b LDAPSyntaxDescription
	var def1 MatchingRuleDescription
	var def2 AttributeTypeDescription
	var def4 ObjectClassDescription
	var def5 DITContentRuleDescription
	var def6 NameFormDescription
	var def7 DITStructureRuleDescription

	var err error

	def0a, err = parseLDAPSyntaxDescription(testSchemaDefinitions[0])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.LDAPSyntaxes = append(schema.LDAPSyntaxes, def0a)
	def0b, err = parseLDAPSyntaxDescription(testSchemaDefinitions[1])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.LDAPSyntaxes = append(schema.LDAPSyntaxes, def0b)

	def1, err = parseMatchingRuleDescription(testSchemaDefinitions[2])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.MatchingRules = append(schema.MatchingRules, def1)

	def2, err = parseAttributeTypeDescription(testSchemaDefinitions[3])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.AttributeTypes = append(schema.AttributeTypes, def2)

	// def3 (MRU) not needed here.

	def4, err = parseObjectClassDescription(testSchemaDefinitions[5])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.ObjectClasses = append(schema.ObjectClasses, def4)

	def5, err = parseDITContentRuleDescription(testSchemaDefinitions[6])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.DITContentRules = append(schema.DITContentRules, def5)

	def6, err = parseNameFormDescription(testSchemaDefinitions[7])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.NameForms = append(schema.NameForms, def6)

	def7, err = parseDITStructureRuleDescription(testSchemaDefinitions[8])
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	schema.DITStructureRules = append(schema.DITStructureRules, def7)

	want := 8
	if got := schema.Counters()[8]; got != want {
		t.Errorf("%s failed: unexpected number of definitions\nwant: %d, got:  %d",
			t.Name(), want, got)
	}

	_ = schema.OID()
	_ = schema.String()
	_ = schema.LDAPSyntaxes.OID()
	_ = schema.MatchingRules.OID()
	_ = schema.AttributeTypes.OID()
	_ = schema.MatchingRuleUse.OID()
	_ = schema.ObjectClasses.OID()
	_ = schema.DITContentRules.OID()
	_ = schema.NameForms.OID()
	_ = schema.DITStructureRules.OID()

	stringBooleanClause(`test`, true)
	stringBooleanClause(`test`, false)

	var mru MatchingRuleUse
	mru = append(mru, MatchingRuleUseDescription{
		OID:         `2.5.13.15`,
		Description: `this is text`,
		Name:        []string{`userRule`},
		Applies:     []string{`cn`, `sn`},
	})
	_ = mru.String()

	var atd AttributeTypeDescription
	atd.Single = true
	atd.mutexBooleanString()
	atd.handleBoolean(`COLLECTIVE`)
	_ = atd.String()

	atd.Single = false
	atd.mutexBooleanString()
	atd.handleBoolean(`COLLECTIVE`)
	atd.handleBoolean(`SINGLE-VALUE`)
	_ = atd.String()
	atd.mutexBooleanString()

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

	_, _ = parseLDAPSyntaxDescription(`( 1.2.3.4
		DESC 'info'
		E-STRING 'BOGUS' )`)
	_, _ = parseMatchingRuleDescription(`( 1.2.3.4
		NAME 'matchingrule'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = parseAttributeTypeDescription(`( 1.2.3.4
		NAME 'attribute'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = parseObjectClassDescription(`( 1.2.3.4
		NAME 'class'
		DESC 'info'
		OBSOLETE
		SUP top
		STRUCTURAL
		MUST c
		E-STRING 'BOGUS' )`)
	_, _ = parseDITContentRuleDescription(`( 1.2.3.4
		NAME 'crule'
		DESC 'info'
		OBSOLETE
		AUX auxClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = parseNameFormDescription(`( 1.2.3.4
		NAME 'form'
		DESC 'info'
		OBSOLETE
		OC structuralClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = parseDITStructureRuleDescription(`( 1
		NAME 'srule'
		DESC 'info'
		OBSOLETE
		FORM form
		E-STRING 'BOGUS' )`)
}
