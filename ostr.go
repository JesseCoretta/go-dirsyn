package dirsyn

/*
ostr.go contains ASN.1 OCTET STRING types and methods.
*/

/*
OctetString implements [§ 3.3.25 of RFC 4517]:

	OctetString = *OCTET

[§ 3.3.25 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.25
*/
type OctetString []byte

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r OctetString) IsZero() bool { return r == nil }

/*
DER returns the ASN.1 DER encoding of the receiver instance alongside an error.
*/
func (r OctetString) DER() (der []byte, err error) {
	var pkt *DERPacket = newDERPacket([]byte{})
	if _, err = pkt.Write(r); err == nil {
		der = pkt.data
	}

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r OctetString) String() string {
	return string(r)
}

/*
Len returns the integer length of the receiver instance.
*/
func (r OctetString) Len() int { return len(r) }

/*
Size returns the summation of the ASN.1 OCTET STRING tag (4) and the byte
size of the receiver instance
*/
func (r OctetString) Size() int { return sizeTagAndLength(tagOctetString, len(r)) }

func (r OctetString) sizeTagged(tag uint64) int { return sizePrimitiveSubBytes(int(tag), r) }

func (r OctetString) tag() uint64 { return uint64(tagOctetString) }

/*
OctetString returns an instance of [OctetString] alongside an error
following an analysis of x in the context of an Octet String.
*/
func (r RFC4517) OctetString(x any) (OctetString, error) {
	return marshalOctetString(x)
}

func octetString(x any) (result Boolean) {
	_, err := marshalOctetString(x)
	result.Set(err == nil)
	return
}

func marshalOctetString(x any) (oct OctetString, err error) {
	var raw []byte
	if raw, err = assertOctetString(x); err != nil {
		return
	}

	runes := []rune(string(raw))
	for i := 0; i < len(runes) && err == nil; i++ {
		var char rune = runes[i]
		if !ucIn(char, octRange) {
			err = errorTxt("Incompatible Octet String character: " + itoa(int(char)))
		}
	}

	if err == nil {
		oct = OctetString(raw)
	}

	return
}

func derWriteOctetString(der *DERPacket, content []byte) int {
	// The length of the value (raw bytes)
	valLen := len(content)

	// Write out the DER header: tag and length. The WriteTagAndLength
	// method returns the number of header bytes written.
	written := der.WriteTagAndLength(classUniversal, false, tagOctetString, valLen)

	// Append the bytes of the OctetString. We use append so that even
	// if r.data was initially empty or too short, it will grow.
	der.data = append(der.data, content...)

	// Update the offset.
	der.offset = len(der.data)

	// Total bytes written is the header length plus the value length.
	return written + valLen
}

func derReadOctetString(x *OctetString, der *DERPacket, tal TagAndLength) (err error) {
	if tal.Tag != tagOctetString {
		err = errorTxt("expected OCTET STRING (tag 4) but got tag " + itoa(tal.Tag))
	} else if der.offset+tal.Length > len(der.data) {
		err = errorTxt("insufficient data for OCTETSTRING")
	} else {
		value := der.data[der.offset : der.offset+tal.Length]
		der.offset += tal.Length
		*x = OctetString(value)
	}

	return
}

func assertOctetString(in any) (raw []byte, err error) {
	switch tv := in.(type) {
	case []byte:
		raw = tv
	case OctetString:
		raw = []byte(tv)
	case string:
		raw = []byte(tv)
	default:
		err = errorBadType("OctetStringMatch")
	}

	return
}

/*
octetStringMatch implements [§ 4.2.27 of RFC 4517].

OID: 2.5.13.17.

[§ 4.2.27 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.27
*/
func octetStringMatch(a, b any) (result Boolean, err error) {

	var A, B []byte
	if A, err = assertOctetString(a); err != nil {
		return
	}

	if B, err = assertOctetString(b); err != nil {
		return
	}

	var res bool
	if res = len(A) == len(B); res {
		for i, ch := range B {
			if res = A[i] == ch; !res {
				break
			}
		}
	}

	result.Set(res)

	return
}

func octetStringOrderingMatch(a, b any, operator byte) (result Boolean, err error) {
	var str1, str2 []byte

	if str1, err = assertOctetString(a); err != nil {
		return
	}

	if str2, err = assertOctetString(b); err != nil {
		return
	}

	mLen := len(str2)
	if len(str1) < mLen {
		mLen = len(str1)
	}

	// Compare octet strings from the first octet to the last
	for i := 0; i < mLen; i++ {
		if operator == GreaterOrEqual {
			if str2[i] < str1[i] {
				result.Set(true)
				return
			} else if str2[i] > str1[i] {
				result.Set(false)
				return
			}
		} else {
			if str1[i] < str2[i] {
				result.Set(true)
				return
			} else if str1[i] > str2[i] {
				result.Set(false)
				return
			}
		}
	}

	// If the strings are identical up to the length of the
	// shorter string, the shorter string precedes the longer
	// string
	if operator == GreaterOrEqual {
		result.Set(len(str2) < len(str1))
	} else {
		result.Set(len(str2) > len(str1))
	}

	return
}
