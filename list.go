package dirsyn

func caseIgnoreListMatch(a, b any) (result Boolean, err error) {
	var strs1, strs2 []string
	if strs1, strs2, err = assertLists(a, b); err != nil {
		return
	}

	if len(strs1) != len(strs2) {
		result.Set(false)
		return
	}

	for idx, slice := range strs1 {
		if !streqf(slice, strs2[idx]) || slice == "" {
			result.Set(false)
			return
		}
	}

	result.Set(true)
	return
}

func assertLists(a, b any) (strs1, strs2 []string, err error) {
	var ok bool

	if strs1, ok = a.([]string); !ok {
		err = errorBadType("list")
		return
	}

	if strs2, ok = b.([]string); !ok {
		err = errorBadType("list")
	}

	return
}
