package dirsyn

/*
enum.go implements ITU-T X.680 ASN.1 ENUMERATED types and methods.
*/

/*
Enumerated implements the ASN.1 ENUMERATED type per [ITU-T Rec. X.680].

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
type Enumerated int

func (r X680) Enumerated(x ...any) (Enumerated, error) {
	return marshalEnumerated(x...)
}

func marshalEnumerated(x ...any) (r Enumerated, err error) {
	if len(x) > 1 {
		switch tv := x[0].(type) {
		case int:
			switch tv2 := x[1].(type) {
			case map[Enumerated]string:
				if _, found := tv2[Enumerated(tv)]; found {
					r = Enumerated(tv)
				}
			default:
				err = errorBadType("X680 Enumerated")
			}
		case int32:
			x[0] = int(tv)
			r, err = marshalEnumerated(x...)
		}
	} else {
		err = errorBadType("X680 Enumerated")
	}

	return
}

/*
Int returns the integer representation of the receiver instance.
*/
func (e Enumerated) Int() int {
	return int(e)
}

// derWriteEnumerated encodes an Enumerated value in DER. We use asn1.Marshal to write the
// integer value (which produces a DER blob with tag 0x02), then we replace the first
// byte with 0x0A (tag ENUMERATED).
func derWriteEnumerated(der *DERPacket, e Enumerated) (n int, err error) {
	var derBytes []byte
	if derBytes, err = asn1m(int(e)); err == nil {
		// TODO: not sure how to trip this in unit tests ...
		// Validate a minimal blob.
		//if len(derBytes) < 2 {
		//	err = errorTxt("invalid DER encoding for enumerated")
		//	return
		//}

		// Replace the INTEGER tag (0x02) with the ENUMERATED tag (0x0A).
		derBytes[0] = 0x0A // 10 in decimal

		// Append to the DERPacket (using dynamic allocation).
		der.data = append(der.data, derBytes...)
		n = len(derBytes)
	}

	return
}

// derReadEnumerated decodes an ENUMERATED value from the DERPacket. The
// allowedValues map is used to validate that only known ENUMERATED
// values are accepted.
func derReadEnumerated(x *Enumerated, der *DERPacket,
	tal TagAndLength, allowedValues map[Enumerated]string) (err error) {

	if tal.Tag != tagEnum {
		err = errorTxt("expected ENUMERATED (tag 10) but got tag " + itoa(tal.Tag))
	} else if der.offset+tal.Length > len(der.data) {
		err = errorTxt("insufficient data for ENUMERATED")
	} else {
		content := der.data[der.offset : der.offset+tal.Length]
		der.offset += tal.Length

		// Reconstruct a DER blob for an INTEGER: asn1.Unmarshal expects tag 0x02.
		tmp := make([]byte, tal.Length+2)
		tmp[0] = 0x02             // INTEGER tag
		tmp[1] = byte(tal.Length) // length byte
		copy(tmp[2:], content)

		var intVal int
		if _, err = asn1um(tmp, &intVal); err == nil {
			// Validate using allowedValues.
			if _, ok := allowedValues[Enumerated(intVal)]; !ok {
				err = errorTxt("invalid ENUMERATED value: " + itoa(x.Int()))
			} else {
				*x = Enumerated(intVal)
			}
		}
	}

	return
}
