package dirsyn

func errorBadLength(name string, length int) error {
	return mkerr(`Invalid length '` + fmtInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return mkerr(`Incompatible input type for ` + name)
}

func errorTxt(txt string) error {
	return mkerr(txt)
}

var (
	nilBEREncodeErr   error = mkerr("Cannot BER encode nil instance")
	unknownBERPacket  error = mkerr("Unidentified BER packet; cannot process")
	endOfFilterErr    error = mkerr("Unexpected end of filter")
	invalidFilterErr  error = mkerr("Invalid or malformed filter")
	emptyFilterSetErr error = mkerr("Zero or invalid filter SET")
)
