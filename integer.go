package dirsyn

import "math/big"

/*
Integer aliases [big.Int] to implement an unbounded Integer syntax.

From [§ 3.3.16 of RFC 4517]:

	Integer = ( HYPHEN LDIGIT *DIGIT ) / number

[§ 3.3.16 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.16
*/
type Integer big.Int

/*
Integer returns an instance of Integer alongside an error following an
analysis of x in the context of an ASN.1 Integer.
*/
func (r RFC4517) Integer(x any) (i Integer, err error) {
	var _i *big.Int
	if _i, err = assertNumber(x); err == nil {
		i = Integer(*_i)
	}

	return
}

func (r Integer) cast() *big.Int {
	a := big.Int(r)
	return &a
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
		if r.cast().Sign() < 0 {
			bts[0] = byte(0x01)
		}
		bts = append(bts, r.cast().Bytes()...)
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
		_r := big.NewInt(0)
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
IsZero returns a Boolean value indicative of a nil, or unset, receiver.
*/
func (r Integer) IsZero() bool {
	return len(r.cast().Bytes()) == 0
}

/*
String returns the string representation of the receiver instance. If the
receiver is unset, `0` is returned.
*/
func (r Integer) String() (s string) {
	s = `0`
	if !r.IsZero() {
		s = r.cast().String()
	}

	return
}

/*
Eq returns a Boolean value indicative of whether the receiver is equal to
the value provided.

Valid input types are string, int64, uint64, int, uint, *[math/big.Int] and [Integer].

Any input that represents an unspecified number guarantees a false return.

See also [Integer.Ne].
*/
func (r Integer) Eq(n any) (is bool) {
	switch tv := n.(type) {
	case *big.Int:
		is = r.cast().Cmp(tv) == 0
	case Integer:
		is = r.cast().Cmp(tv.cast()) == 0
	case string:
		if nf, ok := big.NewInt(0).SetString(tv, 10); ok {
			is = r.cast().Cmp(nf) == 0
		}
	case uint64:
		is = r.cast().Uint64() == tv
	case uint:
		is = r.cast().Uint64() == uint64(tv)
	case int:
		is = r.cast().Int64() == int64(tv)
	}

	return
}

/*
Ne returns a Boolean value indicative of whether the receiver is NOT equal
to the value provided.

This method wraps [Integer.Eq] in negated context, and operates under the
same constraints.
*/
func (r Integer) Ne(n any) bool { return !r.Eq(n) }

/*
Gt returns a boolean value indicative of whether the receiver is greater than
the value provided.

Valid input types are string, int64, uint64, int, uint, *[math/big.Int] and [Integer].

Any input that represents an unspecified number guarantees a false return.
*/
func (r Integer) Gt(n any) (is bool) {
	switch tv := n.(type) {
	case *big.Int:
		is = r.cast().Cmp(tv) == 1
	case Integer:
		is = r.cast().Cmp(tv.cast()) == 1
	case string:
		if nf, ok := big.NewInt(0).SetString(tv, 10); ok {
			is = r.cast().Cmp(nf) == 1
		}
	case uint64:
		is = r.cast().Uint64() > tv
	case uint:
		is = r.cast().Uint64() > uint64(tv)
	case int:
		is = r.cast().Int64() > int64(tv)
	}
	return
}

/*
Ge returns a boolean value indicative of whether the receiver is greater than
or equal to the value provided.

This method is merely a convenient wrapper to an ORed call of the [Integer.Gt]
and [Integer.Eq] methods.

Valid input types are string, int64, uint64, int, uint, *[math/big.Int] and [Integer].

Any input that represents an unspecified number guarantees a false return.
*/
func (r Integer) Ge(n any) (is bool) {
	return r.Gt(n) || r.Eq(n)
}

/*
Lt returns a boolean value indicative of whether the receiver is less than
the value provided.

Valid input types are string, int64, uint64, int, uint, *[math/big.Int] and [Integer].

Any input that represents an unspecified number guarantees a false return.
*/
func (r Integer) Lt(n any) (is bool) {
	switch tv := n.(type) {
	case *big.Int:
		is = r.cast().Cmp(tv) == -1
	case Integer:
		is = r.cast().Cmp(tv.cast()) == -1
	case string:
		if nf, ok := big.NewInt(0).SetString(tv, 10); ok {
			is = r.cast().Cmp(nf) == -1
		}
	case uint64:
		is = r.cast().Uint64() < tv
	case uint:
		is = r.cast().Uint64() < uint64(tv)
	case int:
		is = r.cast().Int64() < int64(tv)
	}
	return
}

/*
Le returns a boolean value indicative of whether the receiver is less than or
equal to the value provided.

This method is merely a convenient wrapper to an ORed call of the [Integer.Lt]
and [Integer.Eq] methods.

Valid input types are string, int64, uint64, int, uint, *[math/big.Int] and [Integer].

Any input that represents an unspecified number guarantees a false return.
*/
func (r Integer) Le(n any) (is bool) {
	return r.Lt(n) || r.Eq(n)
}

func assertInt(x any) (i *big.Int, err error) {
	switch tv := x.(type) {
	case int:
		i = big.NewInt(0).SetInt64(int64(tv))
	case int8:
		i = big.NewInt(0).SetInt64(int64(tv))
	case int16:
		i = big.NewInt(0).SetInt64(int64(tv))
	case int32:
		i = big.NewInt(0).SetInt64(int64(tv))
	case int64:
		i = big.NewInt(0).SetInt64(tv)
	default:
		err = errorBadType("Incompatible int")
	}

	return
}

func assertUint(x any) (i *big.Int, err error) {
	switch tv := x.(type) {
	case uint:
		i = big.NewInt(0).SetUint64(uint64(tv))
	case uint8:
		i = big.NewInt(0).SetUint64(uint64(tv))
	case uint16:
		i = big.NewInt(0).SetUint64(uint64(tv))
	case uint32:
		i = big.NewInt(0).SetUint64(uint64(tv))
	case uint64:
		i = big.NewInt(0).SetUint64(tv)
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
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Integer", 0)
			return
		}

		var ok bool
		i, ok = big.NewInt(0).SetString(tv, 10)
		if !ok {
			err = errorTxt("Unable to convert string '" + tv + "' to Integer")
		} else if hasPfx(tv, `-`) {
			i.Neg(i)
		}
	default:
		err = errorBadType("Integer")
	}

	return
}
