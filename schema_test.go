package dirsyn

import "testing"

func TestSubschemaSubentry(t *testing.T) {
	schema := NewSubschemaSubentry()

	for idx, err := range []error{
		schema.RegisterAttributeType(testSchemaDefinitions[0]),
		schema.RegisterAttributeType(testSchemaDefinitions[1]),
		schema.RegisterAttributeType(testSchemaDefinitions[2]),
		schema.RegisterAttributeType(testSchemaDefinitions[3]),
		schema.RegisterAttributeType(testSchemaDefinitions[4]),
		schema.RegisterAttributeType(testSchemaDefinitions[5]),
		schema.RegisterAttributeType(testSchemaDefinitions[6]),
		schema.RegisterAttributeType(testSchemaDefinitions[7]),
		schema.RegisterObjectClass(testSchemaDefinitions[8]),
		schema.RegisterObjectClass(testSchemaDefinitions[9]),
		schema.RegisterNameForm(testSchemaDefinitions[10]),
		schema.RegisterDITStructureRule(testSchemaDefinitions[11]),
	} {
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		}
	}

	// register a custom syntax
	schema.RegisterLDAPSyntax(`ldapSyntaxes: ( 1.3.6.1.4.1.56521.101.2.1.4                             
          DESC 'X.680, cl. 32.3: ObjectIdentifierValue'                 
          X-PATTERN '^\{([a-z](-?[A-Za-z0-9]+)*(\(\d+\))?)(\s([a-z](-?[A-Za-z0-9]+)*(\(\d+\))))*\}$'
          X-ORIGIN 'RFC1234' )`)

	syn := schema.LDAPSyntaxes[23] // INTEGER ASN.1 type
	if result := syn.Verify(`1`); !result.True() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s\n",
			t.Name(), `TRUE`, result)
		return
	}

	syn = schema.LDAPSyntaxes[len(schema.LDAPSyntaxes)-1]
	if result := syn.Verify(`{joint-iso-itu-t(2) uuid(25)}`); !result.True() {
		t.Errorf("%s [custom syntax] failed:\nwant: %s\ngot:  %s\n",
			t.Name(), `TRUE`, result)
		return
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
}

func TestSubschemaSubentry_codecov(t *testing.T) {

	stringBooleanClause(`test`, true)
	stringBooleanClause(`test`, false)

	var mru MatchingRuleUse
	mru = append(mru, MatchingRuleUseDescription{
		NumericOID:  `2.5.13.15`,
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

	_, _ = marshalLDAPSyntaxDescription(`( 1.2.3.4
		DESC 'info'
		E-STRING 'BOGUS' )`)
	_, _ = marshalMatchingRuleDescription(`( 1.2.3.4
		NAME 'matchingrule'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = marshalAttributeTypeDescription(`( 1.2.3.4
		NAME 'attribute'
		DESC 'info'
		OBSOLETE
		SYNTAX 1.2.3.4
		E-STRING 'BOGUS' )`)
	_, _ = marshalObjectClassDescription(`( 1.2.3.4
		NAME 'class'
		DESC 'info'
		OBSOLETE
		SUP top
		STRUCTURAL
		MUST c
		E-STRING 'BOGUS' )`)
	_, _ = marshalDITContentRuleDescription(`( 1.2.3.4
		NAME 'crule'
		DESC 'info'
		OBSOLETE
		AUX auxClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = marshalNameFormDescription(`( 1.2.3.4
		NAME 'form'
		DESC 'info'
		OBSOLETE
		OC structuralClass
		MUST cn
		E-STRING 'BOGUS' )`)
	_, _ = marshalDITStructureRuleDescription(`( 1
		NAME 'srule'
		DESC 'info'
		OBSOLETE
		FORM form
		E-STRING 'BOGUS' )`)
}

var testSchemaDefinitions []string = []string{
	`attributeType: ( 2.5.4.0
	        NAME 'objectClass'
	        EQUALITY objectIdentifierMatch
	        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
	        X-ORIGIN 'RFC4512' )`,
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
	`( 1.3.6.1.4.1.56521.999.1234
                NAME 'applicationProcessNameForm'
                OC applicationProcess
                MUST cn
                X-ORIGIN 'FAKE' )`,
	`( 1
		NAME 'applicationProcessStructure'
		FORM applicationProcessNameForm
                SUP 1 )`,
}
