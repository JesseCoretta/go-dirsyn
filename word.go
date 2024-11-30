package dirsyn

func wordMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	str1, err = assertString(a, 1, "word")
	if err != nil {
		return
	}

	str2, err = assertString(b, 1, "word")
	if err != nil {
		return
	}

	// Split the attribute value into words
	words := fields(str2)

	// Check if any word matches the assertion value
	var found bool
	for _, word := range words {
		if found = streqf(word, str1); found {
			break
		}
	}

	result.Set(found)
	return
}

/*
TODO: dig deeper into other impls. to determine best (or most common)
practice to adopt.
*/
func keywordSplit(input string) (out []string) {
	bld := newStrBuilder()

	for _, char := range input {
		if isSpace(char) || isPunct(char) {
			if bld.Len() > 0 {
				out = append(out, bld.String())
				bld.Reset()
			}
		} else {
			bld.WriteRune(char)
		}
	}

	if bld.Len() > 0 {
		out = append(out, bld.String())
	}

	return
}

func keywordMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, err = assertString(a, 1, "keyword"); err != nil {
		return
	}

	if str2, err = assertString(b, 1, "keyword"); err != nil {
		return
	}

	keys := keywordSplit(str2)
	var found bool
	for _, key := range keys {
		if found = streqf(key, str1); found {
			break
		}
	}

	result.Set(found)
	return
}
