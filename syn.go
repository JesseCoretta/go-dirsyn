package dirsyn

/*
SyntaxVerification implements a closure function signature meant to be
honored by functions or methods intended to verify the syntax of a value.
*/
type SyntaxVerification func(any) Boolean

var syntaxVerifiers map[string]SyntaxVerification = map[string]SyntaxVerification{
	`1.3.6.1.4.1.1466.115.121.1.3`:  attributeTypeDescription,
	`1.3.6.1.4.1.1466.115.121.1.6`:  bitString,
	`1.3.6.1.4.1.1466.115.121.1.7`:  boolean,
	`1.3.6.1.4.1.1466.115.121.1.11`: countryString,
	`1.3.6.1.4.1.1466.115.121.1.14`: deliveryMethod,
	`1.3.6.1.4.1.1466.115.121.1.15`: directoryString,
	`1.3.6.1.4.1.1466.115.121.1.16`: dITContentRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.17`: dITStructureRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.12`: dN,
	`1.3.6.1.4.1.1466.115.121.1.21`: enhancedGuide,
	`1.3.6.1.4.1.1466.115.121.1.22`: facsimileTelephoneNumber,
	`1.3.6.1.4.1.1466.115.121.1.23`: fax,
	`1.3.6.1.4.1.1466.115.121.1.24`: generalizedTime,
	`1.3.6.1.4.1.1466.115.121.1.25`: guide,
	`1.3.6.1.4.1.1466.115.121.1.26`: iA5String,
	`1.3.6.1.4.1.1466.115.121.1.27`: integer,
	`1.3.6.1.4.1.1466.115.121.1.28`: jPEG,
	`1.3.6.1.4.1.1466.115.121.1.54`: lDAPSyntaxDescription,
	`1.3.6.1.4.1.1466.115.121.1.30`: matchingRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.31`: matchingRuleUseDescription,
	`1.3.6.1.4.1.1466.115.121.1.34`: nameAndOptionalUID,
	`1.3.6.1.4.1.1466.115.121.1.35`: nameFormDescription,
	`1.3.6.1.4.1.1466.115.121.1.36`: numericString,
	`1.3.6.1.4.1.1466.115.121.1.37`: objectClassDescription,
	`1.3.6.1.4.1.1466.115.121.1.40`: octetString,
	`1.3.6.1.4.1.1466.115.121.1.38`: oID,
	`1.3.6.1.4.1.1466.115.121.1.39`: otherMailbox,
	`1.3.6.1.4.1.1466.115.121.1.41`: postalAddress,
	`1.3.6.1.4.1.1466.115.121.1.44`: printableString,
	`1.3.6.1.4.1.1466.115.121.1.58`: substringAssertion,
	`1.3.6.1.4.1.1466.115.121.1.50`: telephoneNumber,
	`1.3.6.1.4.1.1466.115.121.1.51`: teletexTerminalIdentifier,
	`1.3.6.1.4.1.1466.115.121.1.52`: telexNumber,
	`1.3.6.1.4.1.1466.115.121.1.53`: uTCTime,
}
