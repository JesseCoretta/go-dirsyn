package dirsyn

import (
	"encoding/asn1"
	"math/big"
)

/*
Integer aliases [big.Int] to implement an unbounded ASN.1 INTEGER syntax
and matching rule capabilities.

From [§ 3.3.16 of RFC 4517]:

	Integer = ( HYPHEN LDIGIT *DIGIT ) / number

[§ 3.3.16 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.16
*/
type Integer big.Int

func (r Integer) tag() uint64 {
	return uint64(tagInteger)
}

/*
DER returns the ASN.1 DER encoding of the receiver instance alongside an error.
*/
func (r Integer) DER() (der []byte, err error) {
	var pkt *DERPacket = newDERPacket([]byte{})
	if _, err = pkt.Write(r); err == nil {
		der = pkt.data
	}

	return
}

/*
Integer returns an instance of Integer alongside an error following an
analysis of x in the context of an ASN.1 Integer.

x may be any Go primitive number, *[big.Int], string or []byte.  If x
is a []byte instance, it is assumed to be ASN.1 DER encoded bytes.
*/
func (r RFC4517) Integer(x any) (Integer, error) {
	return marshalInteger(x)
}

func marshalInteger(x any) (i Integer, err error) {
	var _i *big.Int
	if _i, err = assertNumber(x); err == nil {
		i = Integer(*_i)
	}

	return
}

func integer(x any) (result Boolean) {
	_, err := marshalInteger(x)
	result.Set(err == nil)
	return
}

/*
Cast unwraps and returns the underlying instance of *[big.Int].
*/
func (r Integer) Cast() *big.Int {
	a := big.Int(r)
	return &a
}

/*
UUID returns the [UUID] representation of the receiver instance.
*/
func (r Integer) UUID() (u UUID) {
	if !r.IsZero() {
		bts := r.Bytes()
		if len(bts) == 17 {
			if bts[0] == 0x00 || bts[0] == 0x01 {
				bts = bts[1:]
			}
		}

		var _u [16]uint8
		copy(_u[16-len(bts):], bts)

		if ret, err := uuidFromBytes(_u[:]); err == nil {
			u = UUID([16]uint8(ret))
		}
	}

	return
}

/*
Bytes wraps [big.Int.Bytes].

Note that the return value is a big endian byte sequence.

Also note that the return value will bear a leading 0x0 if the number is
zero (0) or more, or a leading 0x1 if the number is negative.
*/
func (r Integer) Bytes() (bts []byte) {
	if !r.IsZero() {
		bts = []byte{0x00}
		if r.Cast().Sign() < 0 {
			bts[0] = byte(0x01)
		}
		bts = append(bts, r.Cast().Bytes()...)
	}
	return
}

/*
SetBytes wraps [big.Int.SetBytes].

Note that input value "bts" must be a a big endian byte sequence.

Also note that if encoding bytes manually for submission to this method,
a leading 0x1 signifies the number is negative. A leading 0x0 indicates
the number is unsigned (zero (0) or more) and is optional.
*/
func (r *Integer) SetBytes(bts []byte) {
	if len(bts) > 0 {
		_r := newBigInt(0)
		var neg bool
		if bts[0] == 0x01 {
			bts = bts[1:]
			neg = true
		} else if bts[0] == 0x00 {
			bts = bts[1:]
		}

		_r.SetBytes(bts)
		if neg {
			_r.Neg(_r)
		}
		*r = Integer(*_r)
	}
}

/*
Size returns the summation of the receiver byte size and the ASN.1
INTEGER tag value (2).
*/
func (r Integer) Size() int {
	return r.sizeTagged(r.tag())
}

func (r Integer) sizeTagged(tag uint64) int {
	return sizeTagAndLength(int(tag), len(r.Bytes()))
}

/*
IsZero returns a Boolean value indicative of a nil, or unset, receiver.
*/
func (r Integer) IsZero() bool {
	return len(r.Cast().Bytes()) == 0
}

/*
String returns the string representation of the receiver instance. If the
receiver is unset, `0` is returned.
*/
func (r Integer) String() (s string) {
	s = `0`
	if !r.IsZero() {
		s = r.Cast().String()
	}

	return
}

func derWriteInteger(der *DERPacket, content []byte) int {
	// Append the DER-encoded integer bytes to the data slice.
	der.data = append(der.data, content...)
	der.offset = len(der.data)
	return len(content)
}

func derReadInteger(x *Integer, der *DERPacket, tal TagAndLength) (err error) {
	if tal.Tag != tagInteger {
		err = errorTxt("expected INTEGER (tag 2), but got tag " + itoa(tal.Tag))
		return
	} else if der.offset+tal.Length > len(der.data) {
		err = errorTxt("insufficient bytes for INTEGER")
		return
	}

	encodedValue := der.data[der.offset : der.offset+tal.Length]
	der.offset += tal.Length

	// Convert to big.Int.
	i := newBigInt(0)
	i.SetBytes(encodedValue)

	// Handle DER sign rules. If the first byte has MSB set (negative),
	// we should ensure proper two's complement behavior.
	if len(encodedValue) > 0 && encodedValue[0]&0x80 != 0 {
		// Negative number.
		i.SetBytes(encodedValue)
		// Compute 2^(8*len(encodedValue)).
		bitLen := uint(len(encodedValue) * 8)
		twoPow := newBigInt(1)
		twoPow.Lsh(twoPow, bitLen)
		// Adjust: result = i - 2^(8*len).
		i.Sub(i, twoPow)
	} else {
		i.SetBytes(encodedValue)
	}

	*x = Integer(*i)

	return nil
}

func assertInt(x any) (i *big.Int, err error) {
	switch tv := x.(type) {
	case int:
		i = newBigInt(0).SetInt64(int64(tv))
	case int8:
		i = newBigInt(0).SetInt64(int64(tv))
	case int16:
		i = newBigInt(0).SetInt64(int64(tv))
	case int32:
		i = newBigInt(0).SetInt64(int64(tv))
	case int64:
		i = newBigInt(0).SetInt64(tv)
	default:
		err = errorBadType("Incompatible int")
	}

	return
}

func assertUint(x any) (i *big.Int, err error) {
	switch tv := x.(type) {
	case uint:
		i = newBigInt(0).SetUint64(uint64(tv))
	case uint8:
		i = newBigInt(0).SetUint64(uint64(tv))
	case uint16:
		i = newBigInt(0).SetUint64(uint64(tv))
	case uint32:
		i = newBigInt(0).SetUint64(uint64(tv))
	case uint64:
		i = newBigInt(0).SetUint64(tv)
	default:
		err = errorBadType("Incompatible uint")
	}

	return
}

func assertNumber(x any) (i *big.Int, err error) {
	switch tv := x.(type) {
	case int, int8, int16, int32, int64:
		i, err = assertInt(tv)
	case uint, uint8, uint16, uint32, uint64:
		i, err = assertUint(tv)
	case Integer:
		i = tv.Cast()
	case *big.Int:
		i = tv
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Integer", 0)
			return
		}

		var ok bool
		i, ok = newBigInt(0).SetString(tv, 10)
		if !ok {
			err = errorTxt("Unable to convert string '" + tv + "' to Integer")
		} else if hasPfx(tv, `-`) {
			i.Neg(i)
		}
	case []byte:
		// assume DER-encoding
		_, err = asn1.Unmarshal(tv, &i)
	default:
		err = errorBadType("Integer")
	}

	return
}

func isIntegerType(x any) (is bool) {
	switch x.(type) {
	case int, int8, int16, int32, int64:
		is = true
	}

	return
}

func isNegativeInteger(x any) (is bool) {
	switch tv := x.(type) {
	case int:
		is = tv < 0
	case int8:
		is = tv < 0
	case int16:
		is = tv < 0
	case int32:
		is = tv < 0
	case int64:
		is = tv < 0
	}

	return
}

func castInt64(x any) (i int64, err error) {
	switch tv := x.(type) {
	case int:
		i = int64(tv)
	case int8:
		i = int64(tv)
	case int16:
		i = int64(tv)
	case int32:
		i = int64(tv)
	case int64:
		i = tv
	default:
		err = errorBadType("any2int64")
	}

	return
}

func castUint64(x any) (i uint64, err error) {
	switch tv := x.(type) {
	case uint:
		i = uint64(tv)
	case uint8:
		i = uint64(tv)
	case uint16:
		i = uint64(tv)
	case uint32:
		i = uint64(tv)
	case uint64:
		i = tv
	default:
		err = errorBadType("any2uint64")
	}

	return
}

/*
integerMatch implements [§ 4.2.19 of RFC 4517].

OID: 2.5.13.14

[§ 4.2.19 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.19
*/
func integerMatch(a, b any) (Boolean, error) {
	return integerMatchingRule(a, b)
}

/*
integerOrderingMatch implements [§ 4.2.20 of RFC 4517].

OID: 2.5.13.15

[§ 4.2.20 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.20
*/
func integerOrderingMatch(a, b any, operator byte) (Boolean, error) {
	return integerMatchingRule(a, b, operator)
}

/*
integerFirstComponentMatch implements [§ 4.2.18 of RFC 4517].

OID: 2.5.13.29

[§ 4.2.18 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.18
*/
func integerFirstComponentMatch(a, b any) (result Boolean, err error) {

	// Use reflection to handle the attribute value.
	// This value MUST be a struct (SEQUENCE).
	realValue := assertFirstStructField(a)
	if realValue == nil {
		result.Set(false)
		return
	}

	field, nerr := assertNumber(realValue)
	if nerr != nil {
		err = nerr
		return
	}

	if assertValue := assertFirstStructField(b); assertValue == nil {
		assert, aerr := assertNumber(b)
		err = aerr
		result.Set(streq(field.String(), assert.String()))
	} else {
		assert, aerr := assertNumber(assertValue)
		err = aerr
		result.Set(streq(field.String(), assert.String()))
	}

	return
}

func integerMatchingRule(a, b any, operator ...byte) (Boolean, error) {
	var result Boolean

	bint1, err1 := assertNumber(a)
	if err1 != nil {
		return result, err1
	}
	i1 := Integer(*bint1)

	bint2, err2 := assertNumber(b)
	if err2 != nil {
		return result, err2
	}
	i2 := Integer(*bint2)

	result.Set(compareIntegerInteger(i1, i2, operator...))

	return result, nil
}

func compareIntegerInteger(i, tv Integer, operator ...byte) (is bool) {
	cmp := i.Cast().Cmp(tv.Cast())

	switch len(operator) {
	case 0:
		is = cmp == 0
	default:
		if operator[0] == GreaterOrEqual {
			is = 0 >= cmp
		} else {
			is = cmp <= 0
		}
	}

	return
}
