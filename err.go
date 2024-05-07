package dirsyn

func errorBadLength(name string, length int) error {
	return newErr(`Invalid length '` + fmtInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return newErr(`Incompatible input type for ` + name)
}

func errorTxt(txt string) error {
	return newErr(txt)
}
