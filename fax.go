package dirsyn

import (
	"encoding/asn1"
	"encoding/hex"
)

/*
G3FacsimileBodyPart implements [clause 7.4.2 of ITU-T Rec. X.420]:

	G3FacsimileBodyPart ::= SEQUENCE {
	    parameters G3FacsimileParameters,
	    data       G3FacsimileData
	}

[clause 7.4.2 of ITU-T Rec. X.420]: https://www.itu.int/rec/T-REC-X.420
*/
type G3FacsimileBodyPart struct {
	Parameters G3FacsimileParameters `asn1:"set"`

	// Data implements G3FacsimileData defined in ITU Rec. X.420.
	// G3FacsimileData ::= SEQUENCE OF BIT STRING
	Data []asn1.BitString `asn1:"tag:3,sequence"`
}

/*
G3FacsimileData implements G3FacsimileData defined in [ITU Rec. X.420].

	G3FacsimileData ::= SEQUENCE OF BIT STRING

[clause 7.4.2 of ITU-T Rec. X.420]: https://www.itu.int/rec/T-REC-X.420
*/
type G3FacsimileData []asn1.BitString

type G3FacsimileParameters struct {
	NumberOfPages      int            `asn1:"tag:0,optional"`
	NonBasicParameters asn1.BitString `asn1:"tag:1,optional"`
}

/*
G3FacsimileNonBasicParameters implements [Figure 2, Part 28 of 29 of ITU-T
Rec. X.411]:

	G3FacsimileNonBasicParameters ::= BIT STRING {
	     two-dimensional           (8),  -- As defined in ITU-T Recommendation T.30
	     fine-resolution           (9),  -- unlimited-length (20) -- These bit values are chosen such that when
	     b4-length                 (21), -- encoded using ASN.1 Basic Encoding Rules
	     a3-width                  (22), -- the resulting octets have the same values
	     b4-width                  (23), -- as for T.30 encoding
	     t6-coding                 (25), -- uncompressed (30), -- Trailing zero bits are not significant.
	     width-middle-864-of-1728  (37), -- It is recommended that implementations
	     width-middle-1216-of-1728 (38), -- should not encode more than 32 bits unless
	     resolution-type           (44), -- higher numbered bits are non-zero.
	     resolution-400x400        (45),
	     resolution-300x300        (46),
	     resolution-8x15           (47),
	     edi                       (49),
	     dtm                       (50),
	     bft                       (51),
	     mixed-mode                (58),
	     character-mode            (60),
	     twelve-bits               (65),
	     preferred-huffmann        (66),
	     full-colour               (67),
	     jpeg                      (68),
	     processable-mode-26       (71) }

[Figure 2, Part 28 of 29 of ITU-T Rec. X.411]: https://www.itu.int/rec/T-REC-X.411
*/
type G3FacsimileNonBasicParameters asn1.BitString

/*
Shift bit-shifts the input value bitPos into the receiver instance.
*/
func (r *G3FacsimileNonBasicParameters) Shift(bitPos int) {
	idx := bitPos / 8
	off := bitPos % 8
	r.Bytes[idx] |= 1 << (7 - off)
}

/*
Fax implements an ASN.1 CHOICE of [G3FacsimileBodyPart].
*/
type Fax struct {
	G3Facsimile G3FacsimileBodyPart
}

/*
Fax returns an instance of [Fax] alongside an error following an attempt
to unmarshal x.
*/
func (r RFC4517) Fax(x any) (fax Fax, err error) {
	var b []byte
	switch tv := x.(type) {
	case string:
		if b, err = hex.DecodeString(tv); err != nil {
			return
		}
	case []byte:
		b = tv
	default:
		err = errorBadType("Fax")
		return
	}

	body := new(G3FacsimileBodyPart)

	var rest []byte
	if rest, err = asn1um(b, body); err == nil {
		if len(rest) > 0 {
			err = errorTxt("Extra left-over content found during ASN.1 unmarshal: '" +
				string(rest) + "'")
		} else {
			fax.G3Facsimile = *body
		}
	}

	return
}

/*
Encode returns the encoded ASN.1 bytes of the receiver instance.
*/
func (r Fax) Encode() (b []byte, err error) {
	var x []byte
	if x, err = asn1m(r.G3Facsimile); err == nil {
		b = make([]byte, hex.EncodedLen(len(x)))
		_ = hex.Encode(b, x)
	}

	return
}
