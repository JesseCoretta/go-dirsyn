package dirsyn

/*
UniversalString implements the Universal Character Set.

	UCS = 0x0000 through 0xFFFF
*/
type UniversalString string

/*
UniversalString returns an instance of [UniversalString] alongside an error
following an analysis of x in the context of a UniversalString.
*/
func (r RFC4517) UniversalString(x any) (UniversalString, error) {
	return marshalUniversalString(x)
}

func universalString(x any) (result Boolean) {
	_, err := marshalUniversalString(x)
	result.Set(err == nil)
	return
}

func marshalUniversalString(x any) (us UniversalString, err error) {
	var raw string

	switch tv := x.(type) {
	case UniversalString:
		raw = string(tv)
	case []byte:
		raw = string(tv)
	case string:
		raw = tv
	default:
		err = errorBadType("UniversalString")
		return
	}

	if !utf8OK(raw) {
		err = errorTxt("invalid UniversalString: failed UTF8 checks")
		return
	}

	us = UniversalString(raw)

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r UniversalString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r UniversalString) IsZero() bool { return len(r) == 0 }
