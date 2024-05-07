package dirsyn

import (
	"testing"
)

func TestDN(t *testing.T) {
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
		if err := r.DN(dn); err != nil {
			t.Errorf("%s failed [%s]: %v", t.Name(), dn, err)
		}
	}
}

func TestNameAndOptionalUID(t *testing.T) {
	var r RFC4517

	for idx, noptuid := range []string{
		`uid=jesse,ou=People,o=example\, co#'10100011'B`,
		`uid=jesse,ou=People,o=example\, co`,
	} {
		if err := r.NameAndOptionalUID(noptuid); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
