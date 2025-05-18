package dirsyn

/*
lstr.go contains LDAPString types and methods.
*/

/*
LDAPString aliases [OctetString] to implement [§ 4.1.2 of RFC 4511].

[§ 4.1.2 of RFC 4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.2
*/
type LDAPString OctetString

/*
LDAPString returns an instance of [LDAPString] alongside an error.
*/
func (r RFC4511) LDAPString(x ...any) (LDAPString, error) {
	return marshalLDAPString(x...)
}

func marshalLDAPString(x ...any) (ls LDAPString, err error) {
	if len(x) > 0 {
		switch tv := x[0].(type) {
		case *DERPacket:
			var o OctetString
			err = tv.Read(&o)
			ls = LDAPString(o)
		case OctetString, string, []byte:
			var o OctetString
			o, err = marshalOctetString(tv)
			ls = LDAPString(o)
		}
	}

	return
}

func (r LDAPString) Size() int {
	return OctetString(r).Size()
}

func (r LDAPString) sizeTagged(tag uint64) int {
	return OctetString(r).sizeTagged(tag)
}

/*
String returns the string representation of the receiver instance.
*/
func (r LDAPString) String() string { return string(r) }
