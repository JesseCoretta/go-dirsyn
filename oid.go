package dirsyn

/*
oid.go handles all OID functionality, which includes both numeric OID and
descriptor forms (e.g: "2.5.4.3" vs. "cn").

Numeric OID functionality is sourced from JesseCoretta/go-objectid.
*/

import (
	"github.com/JesseCoretta/go-objectid"
)

var newNumericOID func(...any) (*objectid.DotNotation, error) = objectid.NewDotNotation

/*
Descriptor implements "descr" per [§ 1.4 of RFC 4512]:

	descr = keystring
	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT       ; "0"-"9"
	LDIGIT  = %x31-39             ; "1"-"9"
	HYPHEN  = %x2D                ; hyphen ("-")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type Descriptor string

/*
NumericOID embeds *[objectid.DotNotation] to implement "numericoid" per
[§ 1.4 of RFC 4512]:

	numericoid = number 1*( DOT number )
	number  = DIGIT / ( LDIGIT 1*DIGIT )

	DIGIT   = %x30 / LDIGIT   ; "0"-"9"
	LDIGIT  = %x31-39         ; "1"-"9"
	DOT     = %x2E            ; period (".")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NumericOID struct {
	*objectid.DotNotation
}

/*
OID returns an error following an analysis of x in the context of either
a numeric OID (numericoid) or descriptor (descr) value.

From [§ 1.4 of RFC 4512]:

	oid = descr / numericoid

See also [NumericOID] and [Descriptor] for ABNF productions.

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
func (r RFC4512) OID(x any) (err error) {
	if _, err = r.NumericOID(x); err == nil {
		return
	} else if _, err = r.Descriptor(x); err == nil {
		return
	}

	err = errorTxt("Input conforms to neither Descriptor nor Numeric OID form")
	return
}

/*
OID is a wrapping alias of [RFC4512.OID].
*/
func (r RFC4517) OID(x any) (err error) {
	var s RFC4512
	err = s.OID(x)
	return
}

/*
NumericOID returns a instance of [NumericOID] alongside an error. See
also [RFC4512.OID].
*/
func (r RFC4512) NumericOID(x any) (NumericOID, error) {
	return marshalNumericOID(x)
}

func oID(x any) (result Boolean) {
	_, err1 := marshalNumericOID(x)
	_, err2 := marshalDescriptor(x)
	result.Set(err1 == nil || err2 == nil)
	return
}

func marshalNumericOID(x any) (noid NumericOID, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Numeric OID"); err != nil {
		return
	}

	var o *objectid.DotNotation
	if o, err = newNumericOID(raw); err == nil {
		noid = NumericOID{o}
	}

	return
}

/*
NumericOID is a wrapping alias of [RFC4512.NumericOID].
*/
func (r RFC4517) NumericOID(x any) (NumericOID, error) {
	return marshalNumericOID(x)
}

/*
Descriptor is a wrapping alias of [RFC4512.Descriptor].
*/
func (r RFC4517) Descriptor(x any) (Descriptor, error) {
	return marshalDescriptor(x)
}

/*
Descriptor returns an instance of [Descriptor] alongside an error. See
also [RFC4512.OID].
*/
func (r RFC4512) Descriptor(x any) (Descriptor, error) {
	return marshalDescriptor(x)
}

func marshalDescriptor(x any) (descr Descriptor, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Descriptor"); err != nil {
		return
	}

	// must begin with an alpha.
	if !isAlpha(rune(raw[0])) {
		err = errorTxt("Incompatible leading character: " + string(raw[0]))
		return
	}

	// can only end in alnum.
	if !isAlphaNumeric(rune(raw[len(raw)-1])) {
		err = errorTxt("Incompatible trailing character: " + string(raw[len(raw)-1]))
		return
	}

	// watch hyphens to avoid contiguous use
	var lastHyphen bool

	// iterate all characters in raw, checking
	// each one for "descr" validity.
	for i := 0; i < len(raw) && err == nil; i++ {
		ch := rune(raw[i])
		switch {
		case isAlphaNumeric(ch):
			lastHyphen = false
		case ch == '-':
			if lastHyphen {
				// cannot use consecutive hyphens
				err = errorTxt("Consecutive hyphens in descriptor")
				break
			}
			lastHyphen = true
		default:
			// invalid character (none of [a-zA-Z0-9\-])
			err = errorTxt("Incompatible character " + string(ch))
		}
	}

	if err == nil {
		descr = Descriptor(raw)
	}

	return
}

func objectIdentifierMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string

	// Assertion OID (num or descr)
	if str1, err = assertString(a, 1, "oid"); err != nil {
		return
	}

	if str2, err = assertString(b, 1, "oid"); err != nil {
		return
	}

	result.Set(oID(str2).True() && streqf(str1, str2))

	return
}

func objectIdentifierFirstComponentMatch(a, b any) (result Boolean, err error) {

	// Use reflection to handle the attribute value.
	// This value MUST be a struct (SEQUENCE).
	realValue := assertFirstStructField(a)
	if realValue == nil {
		result.Set(false)
		return
	}

	field, ok := realValue.(string)
	if !ok {
		err = errorTxt("first component is not an OID")
		return
	}

	// Don't bother going any further if the input
	// realValue is a DITStructureRule,
	// as those don't use OIDs.
	if _, ok := a.(DITStructureRule); ok {
		return
	}

	var str2 string
	if str2, err = assertString(b, 1, "oid"); err != nil {
		return
	} else if res := oID(str2); !res.True() {
		return
	}

	result.Set(streqf(field, str2))

	return
}
