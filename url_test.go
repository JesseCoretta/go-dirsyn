package dirsyn

import (
	"testing"
)

func TestURL(t *testing.T) {

	var r RFC4516

	// NOTE: most of these tests are copied
	// directly from § 4 of RFC4516.
	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: "ldap://localhost:389/dc=example%2Cdc=com?cn%2Csn?sub?(cn%3DJohn%20Doe)?!x-foo%3Dbar,!x-bar",
			Want: "ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(cn=John Doe)?!x-foo=bar,!x-bar",
		},
		{
			Orig: "ldap:///o=University%20of%20Michigan,c=US",
			Want: "ldap:///o=University of Michigan,c=US",
		},
		{
			Orig: "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US",
			Want: "ldap://ldap1.example.net/o=University of Michigan,c=US",
		},
		{
			Orig: "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress",
			Want: "ldap://ldap1.example.net/o=University of Michigan,c=US?postalAddress",
		},
		{
			Orig: "ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
			Want: "ldap://ldap1.example.net:6666/o=University of Michigan,c=US??sub?(cn=Babs Jensen)",
		},
		{
			Orig: "LDAP://ldap1.example.com/c=GB?objectClass?ONE",
			Want: "ldap://ldap1.example.com/c=GB?objectClass?one",
		},
		{
			Orig: "ldap://ldap2.example.com/o=Question%3f,c=US?mail",
			Want: "ldap://ldap2.example.com/o=Question?,c=US?mail",
		},
		{
			Orig: "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)",
			Want: "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=\\00\\00\\00\\04)",
		},
		{
			Orig: "ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US",
			Want: "ldap://ldap.example.com/o=An Example\\, Inc.,c=US",
		},
		{
			Orig: "ldap://ldap.example.net",
			Want: "ldap://ldap.example.net",
		},
		{
			Orig: "ldap://ldap.example.net/",
			Want: "ldap://ldap.example.net",
		},
		{
			Orig: "ldap://ldap.example.net/?",
			Want: "ldap://ldap.example.net",
		},
		{
			Orig: "ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com",
			Want: "ldap:///??sub??e-bindname=cn=Manager,dc=example,dc=com",
		},
		{
			Orig: "ldap:///??sub??!e-bindname=cn=Manager%2cdc=example%2cdc=com",
			Want: "ldap:///??sub??!e-bindname=cn=Manager,dc=example,dc=com",
		},
	}

	for idx, obj := range tests {
		if u, err := r.URL(obj.Orig); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := u.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant '%s'\n\tgot  '%s'", t.Name(), idx, obj.Want, got)
		}
	}
}
