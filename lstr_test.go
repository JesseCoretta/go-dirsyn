package dirsyn

import (
	"testing"
)

func TestLDAPString(t *testing.T) {
	var srcs Sources
	for _, lstring := range []any{
		"cn",
		[]byte("cn"),
		OctetString("cn"),
	} {
		ls, err := srcs.RFC4511().LDAPString(lstring)
		if err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		}
		ls.Size()
		ls.sizeTagged(4)

		der, _ := srcs.X690().DER()
		var o OctetString = OctetString(ls)
		if _, err := der.Write(o); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		} else if err = der.Read(&o); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		}
		_, _ = marshalLDAPString(der)
	}

}
