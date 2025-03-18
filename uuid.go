package dirsyn

import (
	"github.com/google/uuid"
)

/*
UUID aliases [uuid.UUID] to implement RFC 4530.

From [§ 3 of RFC 4122]:

	UUID                   = time-low "-" time-mid "-"
	                         time-high-and-version "-"
	                         clock-seq-and-reserved
	                         clock-seq-low "-" node
	time-low               = 4hexOctet
	time-mid               = 2hexOctet
	time-high-and-version  = 2hexOctet
	clock-seq-and-reserved = hexOctet
	clock-seq-low          = hexOctet
	node                   = 6hexOctet
	hexOctet               = hexDigit hexDigit
	hexDigit =
	      "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9" /
	      "a" / "b" / "c" / "d" / "e" / "f" /
	      "A" / "B" / "C" / "D" / "E" / "F"

[§ 3 of RFC 4122]: https://datatracker.ietf.org/doc/html/rfc4122#section-3
*/
type UUID uuid.UUID

var uuidFromBytes func([]byte) (uuid.UUID, error) = uuid.FromBytes

/*
UUID returns an instance of [UUID] alongside an error.
*/
func (r RFC4530) UUID(x any) (u UUID, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if l := len(tv); l != 36 {
			err = errorBadLength("UUID", len(tv))
			return
		}
		raw = tv
	default:
		err = errorBadType("UUID")
		return
	}

	var _u uuid.UUID
	if _u, err = uuid.Parse(raw); err == nil {
		u = UUID(_u)
	}

	return
}

/*
Cast unwraps and returns the underlying instance of [uuid.UUID].
*/
func (r UUID) Cast() uuid.UUID {
	return uuid.UUID(r)
}

/*
String returns the string representation of the receiver instance.
*/
func (r UUID) String() string {
	return r.Cast().String()
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UUID) IsZero() bool {
	return len(r) == 0
}

/*
Integer returns the [Integer] representation of the receiver instance.
*/
func (r UUID) Integer() (i Integer) {
	if !r.IsZero() {
		_i, _ := assertNumber(0)
		_i.SetBytes(r[:])
		i = Integer(*_i)
	}

	return
}
