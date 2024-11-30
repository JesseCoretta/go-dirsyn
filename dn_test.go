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

	dN(`OU=Sales+CN=J. Smith,DC=example,DC=net`)
	dn, _ := marshalDistinguishedName(`OU=Sales+CN=J. Smith,DC=example,DC=net`)
	_ = dn.RDNs[0].Attributes[0].String()
	dn.RDNs[0].Attributes[0].Equal(dn.RDNs[0].Attributes[0])
	dn.RDNs[0].Attributes[0].EqualFold(dn.RDNs[0].Attributes[0])
	_ = dn.RDNs[0].String()
	dn.RDNs[0].Equal(dn.RDNs[0])
	dn.RDNs[0].EqualFold(dn.RDNs[0])
	_ = dn.String()
	distinguishedNameMatch(dn, `uid=jesse`)
	dn.Equal(dn)
	dn.EqualFold(dn)
	dn.AncestorOf(dn)
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
	marshalDistinguishedName(``)
	marshalDistinguishedName(`A`)
	dn, _ := marshalDistinguishedName([]byte(`uid=jesse,dc=example,dc=com`))
	dn2, _ := marshalDistinguishedName([]byte(`uid=jesse,o=example`))
	uniqueMemberMatch(nil, dn)
	uniqueMemberMatch(dn, nil)
	uniqueMemberMatch(dn, dn)
	uniqueMemberMatch(dn, dn2)
}
