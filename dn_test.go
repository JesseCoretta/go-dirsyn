package dirsyn

import (
	"testing"
)

func TestDistinguishedName(t *testing.T) {
	var r RFC4514
	for _, dn := range []string{
		`uid=jesse,ou=People,o=example\, co`,
		`uid=jesse+uidNumber=5042,ou=People,o=example\, co`,
		`cn=example`,
		`l=z`,
		`l=xy`,
		`l=abc`,
		`UID=jsmith,DC=example,DC=net`,
		`OU=Sales+CN=J. Smith,DC=example,DC=net`,
		`CN=John Smith\, III,DC=example,DC=net`,
		`CN=Before\0dAfter,DC=example,DC=net`,
		`1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com`,
		`CN=Lu\C4\8Di\C4\87`,
	} {
		dn, err := r.DistinguishedName(dn)
		if err != nil {
			t.Errorf("%s failed [%s]: %v", t.Name(), dn, err)
		}
	}

	var r2 RFC4517
	oth, _ := r2.DistinguishedName(`OU=Sales+CN=J. Smith,DC=example,DC=net`)

	dN(`OU=Sales+CN=J. Smith,DC=example,DC=net`)
	dn, _ := marshalDistinguishedName(`OU=Sales+CN=J. Smith,DC=example,DC=net`)
	_ = dn.RDNs[0].Attributes[0].String()
	dn.RDNs[0].Attributes[0].Equal(dn.RDNs[0].Attributes[0])
	dn.RDNs[0].Attributes[0].EqualFold(dn.RDNs[0].Attributes[0])
	_ = dn.RDNs[0].String()
	dn.RDNs[0].Equal(dn.RDNs[0])
	dn.RDNs[0].EqualFold(dn.RDNs[0])
	_ = dn.String()
	distinguishedNameMatch(dn, dn)
	distinguishedNameMatch(dn, `uid=jesse`)
	distinguishedNameMatch(`uid=jesse`, dn)
	distinguishedNameMatch(`uid=jesse`, `uid=jesse`)
	distinguishedNameMatch(`uid=jesse`, `uid=jessi`)
	distinguishedNameMatch(`uid=jesse`, `uid=jesse,ou=people`)
	dn.Equal(dn)
	dn.EqualFold(dn)
	dn.AncestorOf(dn)
	dn.AncestorOfFold(dn)
	dn2 := dn
	dn2.RDNs = dn.RDNs[1:]
	distinguishedNameMatch(dn, dn2)
	distinguishedNameMatch(nil, dn2)
	distinguishedNameMatch(dn, nil)
	dn2.EqualFold(dn)
	dn.EqualFold(dn2)
	dn2.AncestorOf(dn)
	dn2.AncestorOfFold(dn)
	dn.AncestorOf(dn2)
	dn.AncestorOfFold(dn2)
	dn2.RDNs = dn.RDNs[:len(dn.RDNs)-1]
	distinguishedNameMatch(dn2, dn)
	dn2.EqualFold(dn)
	dn.EqualFold(dn2)
	dn2.AncestorOf(dn)
	dn2.AncestorOfFold(dn)
	dn.AncestorOf(dn2)
	dn.AncestorOfFold(dn2)
	dn.RDNs[1].Attributes[0].Type = "dork"
	dn.EqualFold(oth)
	dn.RDNs[0].hasAllAttributes([]*AttributeTypeAndValue{
		{Type: "drink"},
	})
	dn.RDNs[0].hasAllAttributesFold([]*AttributeTypeAndValue{
		{Type: "drink"},
	})
	stripLeadingAndTrailingSpaces("string\\ ")
	parseDN("")
	foldString("A")
	foldString("👩")
	foldString("a_")
	foldRune('A')
	foldRune('a')
	parseDN("=value")
	parseDN("value=")
	parseDN(",=value,")
	parseDN("=value,")

	for _, s := range []string{
		"\\\\",
		"string\\",
		"string\\?",
		"string\\👩👩",
		"string\\ea",
		"string\\f09f91a9",
		"string\\e\\👩1",
		"string\\ex",
		"#01011101",
	} {
		decodeString(s)
		decodeEncodedString(s)
	}

	for _, b := range []bool{
		true,
		false,
	} {
		encodeString("string\\👩👩", b)
		encodeString("string\\", b)
		encodeString("string\\?", b)
		encodeString("string\\? ", b)
		encodeString("=string\\? ", b)
		encodeString("#string\\? ", b)
		encodeString("string\\ea", b)
	}
}

func TestNameAndOptionalUID(t *testing.T) {
	var r RFC4517

	for idx, noptuid := range []string{
		`uid=jesse,ou=People,o=example\, co#'10100011'B`,
		`uid=jesse,ou=People,o=example\, co`,
	} {
		if nou, err := r.NameAndOptionalUID(noptuid); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else {
			marshalNameAndOptionalUID(nou)
			marshalNameAndOptionalUID(nou.DN)
			uniqueMemberMatch(nou, nou)
			distinguishedNameMatch(nou.DN, nil)
		}
	}

	nameAndOptionalUID(`uid=jesse,ou=People,o=example\, co#'10100011'B`)
	marshalNameAndOptionalUID(`uid=jesse,ou=People,o=example\, co#'10100011'B`)
	marshalNameAndOptionalUID(`uid=jesse,ou=People,o=example\, co'10100011'B`)
	marshalNameAndOptionalUID(`uid=jesse,ou=People,o=example\, co#'AAAA0011'B`)
	marshalNameAndOptionalUID(`uid=jesse,ou=People,o=example\, co#''B`)
	marshalNameAndOptionalUID(``)
	marshalDistinguishedName(``)
	marshalDistinguishedName(`A`)
	dn, _ := marshalDistinguishedName([]byte(`uid=jesse,dc=example,dc=com`))
	dn2, _ := marshalDistinguishedName([]byte(`uid=jesse,o=example`))
	uniqueMemberMatch(nil, dn)
	uniqueMemberMatch(dn, "")
	uniqueMemberMatch(dn, dn2)
	uniqueMemberMatch(`uid=jesse`, `uid=jessi`)
	uniqueMemberMatch(`uid=jesse`, `uid=jesse`)
	uniqueMemberMatch(`uid=jesse`, `uid=jesse'10100011'B`)
	uniqueMemberMatch(`uid=jesse#'10100011'B`, `uid=jesse#'10100011'B`)
	uniqueMemberMatch(`uid=jesse#'10100011'B`, `uid=jessi#'10100011'B`)
	uniqueMemberMatch(`uid=jesse#'10100011'B`, `uid=jesse#'10111'B`)
}
