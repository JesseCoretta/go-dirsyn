package dirsyn

/*
bitstring.go implements the ASN.1 BIT STRING type and methods.
*/

import (
	"encoding/asn1"
)

/*
BitString is a type alias of [asn1.BitString], which can conform to [§ 3.3.2
of RFC 4517]:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From [§ 1.4 of RFC 4512]:

	SQUOTE  = %x27 ; single quote ("'")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
*/
type BitString asn1.BitString

/*
String returns the string representation of the receiver instance.
*/
func (r BitString) String() (bs string) {
	if len(r.Bytes)*8 == r.BitLength {
		for _, b := range r.Bytes {
			bs += fuint(uint64(b), 2)
		}

		bs = string(rune('\'')) + bs +
			string(rune('\'')) +
			string(rune('B'))
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r BitString) IsZero() bool { return &r == nil }

/*
BitString returns an error following an analysis of x in the context of
an ASN.1 BIT STRING.
*/
func (r RFC4517) BitString(x any) (bs BitString, err error) {
	var raw []byte
	if raw, err = assertBitString(x); err == nil {
		// Make sure there are enough remaining
		// characters to actually do something.
		if raw, err = verifyBitStringContents(raw); err == nil {
			var tx string
			var bss asn1.BitString

			for i := len(raw); i > 0 && err == nil; i -= 8 {
				tx = string(raw[:i])
				if i-8 >= 0 {
					tx = string(raw[i-8 : i])
				}

				var bd uint64
				bd, err = puint(tx, 2, 8)
				bss.Bytes = append(bss.Bytes, []byte{byte(bd)}...)
			}

			if err == nil {
				if _, err = asn1m(bss); err == nil {
					bss.BitLength = len(bss.Bytes) * 8
					bs = BitString(bss)
				}
			}
		}
	}

	return
}

func assertBitString(x any) (raw []byte, err error) {
	switch tv := x.(type) {
	case []byte:
		if len(tv) == 0 {
			err = errorBadLength("BitString", 0)
			break
		}
		raw = tv
	case string:
		raw, err = assertBitString([]byte(tv))
	default:
		err = errorBadType("BitString")
	}

	return
}

func verifyBitStringContents(raw []byte) ([]byte, error) {
	var err error

	// Last char MUST be 'B' rune, else die.
	if term := raw[len(raw)-1]; term != 'B' {
		err = errorTxt("Incompatible terminating character for BitString: " + string(term))
		return raw, err
	}

	// Trim terminating char
	raw = raw[:len(raw)-1]

	// Make sure there are enough remaining
	// characters to actually do something.
	if len(raw) < 3 {
		err = errorTxt("Incompatible remaining length for BitString: " + fmtInt(int64(len(raw)), 10))
		return raw, err
	}

	// Verify (and then remove) single quotes
	L := raw[0]
	R := raw[len(raw)-1]
	if L != '\'' || R != '\'' {
		err = errorTxt("Incompatible encapsulating characters BitString: " + string(L) + "/" + string(R))
		return raw, err
	}
	raw = raw[1 : len(raw)-1]

	for i := 0; i < len(raw); i++ {
		if !isBinChar(rune(raw[i])) {
			err = errorTxt("Incompatible non-binary character for BitString" + string(raw[i]))
			break
		}
	}

	return raw, err
}