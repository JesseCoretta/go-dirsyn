package dirsyn

/*
isT61Single returns a Boolean value indicative of a character match between input
rune r and one of the runes present within the t61NonContiguous global []rune
instance.
*/
func isT61Single(r rune) (is bool) {
	for _, char := range t61NonContiguous {
		if is = r == char; is {
			break
		}
	}

	return is
}

/*
Deprecated: TeletexString implements the Teletex String, per [ITU-T Rec. T.61]

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
type TeletexString string

/*
String returns the string representation of the receiver instance.
*/
func (r TeletexString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r TeletexString) IsZero() bool { return len(r) == 0 }

/*
Deprecated: TeletexString returns an instance of [TeletexString] alongside
an error following an analysis of x in the context of a Teletex String, per
[ITU-T Rec. T.61].

[ITU-T Rec. T.61]: https://www.itu.int/rec/T-REC-T.61
*/
func (r RFC4517) TeletexString(x any) (TeletexString, error) {
	return marshalTeletexString(x)
}

func teletexString(x any) (result Boolean) {
	_, err := marshalTeletexString(x)
	result.Set(err == nil)
	return
}

func marshalTeletexString(x any) (ts TeletexString, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Teletex String", 0)
			return
		}
		raw = tv
	case []byte:
		ts, err = marshalTeletexString(string(tv))
		return
	default:
		err = errorBadType("Teletex String")
		return
	}

	for i := 0; i < len(raw); i++ {
		char := rune(raw[i])
		if !(isT61RangedRune(char) || isT61Single(char)) {
			err = errorTxt("Incompatible character for Teletex String: " + string(char))
			break
		}
	}

	if err == nil {
		ts = TeletexString(raw)
	}

	return
}
