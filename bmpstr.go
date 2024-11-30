package dirsyn

/*
BMPString implements the Basic Multilingual Plane per [ITU-T Rec. X.680].

The structure for instances of this type is as follows:

	T (30, Ox1E) N (NUM. BYTES) P{byte,byte,byte}

Tag T represents ASN.1 BMPString tag integer 30 (0x1E). Number N is an
int-cast byte value that cannot exceed 255. The remaining bytes, which
may be zero (0) or more in number, define payload P. N must equal size
of payload P.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type BMPString []uint8

/*
String returns the string representation of the receiver instance.

This involves unmarshaling the receiver into a string return value.
*/
func (r BMPString) String() string {
	if len(r) < 3 || r[0] != 0x1E {
		return ""
	}

	length := int(r[1])
	expectedLength := 2 + length*2
	if len(r) != expectedLength {
		return ""
	}

	var result []rune
	for i := 2; i < expectedLength; i += 2 {
		codePoint := (rune(r[i]) << 8) | rune(r[i+1])
		result = append(result, codePoint)
	}

	return string(result)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BMPString) IsZero() bool { return r == nil }

/*
BMPString marshals x into a BMPString (UTF-16) return value, returning
an instance of [BMPString] alongside an error.
*/
func (r X680) BMPString(x any) (BMPString, error) {
	return assertBMPString(x)
}

func assertBMPString(x any) (enc BMPString, err error) {
	var e string
	switch tv := x.(type) {
	case []uint8:
		e = string(tv)
	case BMPString:
		if len(tv) == 0 {
			break
		} else if len(tv) == 2 {
			if tv[0] != 0x1E || tv[1] != 0x0 {
				err = errorTxt("Invalid ASN.1 tag or length octet for empty string")
			} else {
				enc = BMPString{0x1E, 0x0}
			}
			return
		} else {
			if tv[0] != 0x1E {
				err = errorTxt("Invalid ASN.1 tag")
				return
			} else if int(tv[1]) != len(tv[2:]) {
				err = errorTxt("input string encoded length does not match length octet")
				return
			}
		}
	case string:
		e = tv
	default:
		err = errorBadType("BMPString")
		return
	}

	if len(e) == 0 {
		// Zero length values are OK
		enc = BMPString{0x1E, 0x0}
		return
	}

	var result []byte
	result = append(result, 0x1E) // Add BMPString tag (byte(30))

	encoded := utf16Enc([]rune(e))
	length := len(encoded)
	if uint16(length) > uint16(255) {
		err = errorTxt("input string too long for BMPString encoding")
		return
	}
	result = append(result, byte(length))

	for _, char := range encoded {
		result = append(result, byte(char>>8), byte(char&0xFF))
	}

	enc = BMPString(result)

	return
}
