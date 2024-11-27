package dirsyn

import "time"

/*
MatchingRuleAssertion defines a closure signature held by qualifying
function instances intended to implement a particular Matching Rule.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type MatchingRuleAssertion func(any, any) (Boolean, error)

var matchingRuleAssertions map[string]MatchingRuleAssertion = map[string]MatchingRuleAssertion{
	"2.5.13.0":                   objectIdentifierMatch,
	"2.5.13.1":                   distinguishedNameMatch,
	"2.5.13.2":                   caseIgnoreMatch,
	"2.5.13.3":                   caseIgnoreOrderingMatch,
	"2.5.13.4":                   caseIgnoreSubstringsMatch,
	"2.5.13.5":                   caseExactMatch,
	"2.5.13.6":                   caseExactOrderingMatch,
	"2.5.13.7":                   caseExactSubstringsMatch,
	"2.5.13.8":                   numericStringMatch,
	"2.5.13.9":                   numericStringOrderingMatch,
	"2.5.13.10":                  numericStringSubstringsMatch,
	"2.5.13.11":                  caseIgnoreListMatch,
	"2.5.13.12":                  caseIgnoreListSubstringsMatch,
	"2.5.13.13":                  booleanMatch,
	"2.5.13.14":                  integerMatch,
	"2.5.13.15":                  integerOrderingMatch,
	"2.5.13.16":                  bitStringMatch,
	"2.5.13.17":                  octetStringMatch,
	"2.5.13.18":                  octetStringOrderingMatch,
	"2.5.13.20":                  telephoneNumberMatch,
	"2.5.13.21":                  telephoneNumberSubstringsMatch,
	"2.5.13.23":                  uniqueMemberMatch,
	"2.5.13.27":                  generalizedTimeMatch,
	"2.5.13.28":                  generalizedTimeOrderingMatch,
	"2.5.13.29":                  integerFirstComponentMatch,
	"2.5.13.30":                  objectIdentifierFirstComponentMatch,
	"2.5.13.31":                  directoryStringFirstComponentMatch,
	"2.5.13.32":                  wordMatch,
	"2.5.13.33":                  keywordMatch,
	"1.3.6.1.4.1.1466.109.114.1": caseExactIA5Match,
	"1.3.6.1.4.1.1466.109.114.2": caseIgnoreIA5Match,
	"1.3.6.1.4.1.1466.109.114.3": caseIgnoreIA5SubstringsMatch,
}

/*
octetStringMatch implements [§ 4.2.27 of RFC 4517].

OID: 2.5.13.17.

[§ 4.2.27 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.27
*/
func octetStringMatch(a, b any) (result Boolean, err error) {

	var A, B []byte
	if A, err = assertOctetString(a); err != nil {
		return
	}

	if B, err = assertOctetString(b); err != nil {
		return
	}

	var res bool
	if res = len(A) == len(B); res {
		for i, ch := range B {
			if res = A[i] == ch; !res {
				break
			}
		}
	}

	result.Set(res)

	return
}

/*
bitStringMatch returns a Boolean value indicative of a BitStringMatch
as described in [§ 4.2.1 of RFC 4517].

OID: 2.5.13.16

[§ 4.2.1 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.1
*/
func bitStringMatch(a, b any) (result Boolean, err error) {
	var abs, bbs BitString

	if abs, err = marshalBitString(a); err != nil {
		return
	}

	abytes := abs.Bytes
	abits := abs.BitLength

	if bbs, err = marshalBitString(b); err != nil {
		return
	}

	bbytes := bbs.Bytes
	bbits := bbs.BitLength

	// TODO
	//if namedBitList {
	//        // Remove trailing zero bits
	//        abits = stripTrailingZeros(abytes, abits)
	//        bbits = stripTrailingZeros(bbytes, bbits)
	//}

	// Check if both bit strings have the same number of bits
	if abits != bbits {
		result.Set(false)
		return
	}

	// Compare bit strings bitwise
	for i := 0; i < len(abytes); i++ {
		if abytes[i] != bbytes[i] {
			result.Set(false)
			return
		}
	}

	result.Set(true)

	return
}

// stripTrailingZeros removes trailing zero bits and returns the new bit length
func stripTrailingZeros(bytes []byte, bitLength int) (blen int) {
	blen = bitLength
	for i := len(bytes) - 1; i >= 0; i-- {
		for bit := 0; bit < 8; bit++ {
			if (bytes[i] & (1 << bit)) != 0 {
				return blen
			}
			blen--
		}
	}

	return
}

func caseIgnoreSubstringsMatch(a, b any) (result Boolean, err error) {
	result, err = substringsMatch(a, b, true)
	return
}

func caseExactSubstringsMatch(a, b any) (result Boolean, err error) {
	result, err = substringsMatch(a, b, false)
	return
}

func substringsMatch(a, b any, caseIgnore ...bool) (result Boolean, err error) {
	var A, B SubstringAssertion
	if A, err = marshalSubstringAssertion(a); err != nil {
		return
	}

	if B, err = marshalSubstringAssertion(b); err != nil {
		return
	}

	caseHandler := func(val string) string { return val }

	if len(caseIgnore) > 0 {
		if caseIgnore[0] {
			caseHandler = lc
		}
	}

	value := caseHandler(B.String())

	if A.Any == nil {
		err = errorBadType("Missing SubstringAssertion.Any")
		return
	}

	if A.Initial != nil {
		initialStr := caseHandler(string(A.Initial))
		if !hasPfx(value, initialStr) {
			result.Set(false)
			return
		}
		value = trimPfx(value, initialStr)
	}

	anyStr := `*` + trim(caseHandler(string(A.Any)), `*`) + `*`
	substrings := split(anyStr, "*")
	for _, substr := range substrings {
		index := stridx(value, substr)
		if index == -1 {
			result.Set(false)
			return
		}
		value = value[index+len(substr):]
	}

	if A.Final != nil {
		finalStr := caseHandler(string(A.Final))
		if !hasSfx(value, finalStr) {
			result.Set(false)
			return
		}
	}

	result.Set(true)

	return
}

/*
booleanMatch implements [§ 4.2.2 of RFC 4517].

OID: 2.5.13.13.

[§ 4.2.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.2
*/
func booleanMatch(a, b any) (result Boolean, err error) {

	var A, B Boolean
	if A, err = assertBoolean(a); err != nil {
		return
	}
	if B, err = assertBoolean(b); err != nil {
		return
	}

	if A.True() {
		result.Set(B.True())
	} else if A.False() {
		result.Set(B.False())
	} else if A.Undefined() {
		result.Set(B.Undefined())
	}

	return
}

func generalizedTimeMatch(a, b any) (result Boolean, err error) {
	result, err = timeMatch(a, b, 0)
	return
}

func generalizedTimeOrderingMatch(a, b any) (result Boolean, err error) {
	result, err = timeMatch(a, b, 2)
	return
}

/*
timeMatch implements [§ 4.2.16] and [§ 4.2.17] of RFC4517.

[§ 4.2.16 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.16
[§ 4.2.17 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.17
*/
func timeMatch(rcv, assert any, typ int) (result Boolean, err error) {
	var c time.Time
	var utc bool

	switch tv := rcv.(type) {
	case GeneralizedTime:
		c = tv.Cast().UTC()
	case UTCTime:
		c = tv.Cast().UTC()
		utc = true
	case string:
		switch len(tv) {
		case 15:
			var gt GeneralizedTime
			gt, err = marshalGenTime(tv)
			c = gt.Cast().UTC()
		case 10:
			utc = true
			var ut UTCTime
			ut, err = marshalUTCTime(tv)
			c = ut.Cast().UTC()
		default:
			err = errorBadType("GeneralizedTime")
		}
	default:
		err = errorBadType("GeneralizedTime")
	}

	if err != nil {
		return
	}

	var funk func(time.Time) bool
	switch typ {
	case 0:
		funk = func(thyme time.Time) bool {
			return c.Equal(thyme)
		}
	case 2:
		funk = func(thyme time.Time) bool {
			return c.Before(thyme)
		}
	}

	result.Set(compareTimes(assert, utc, funk))

	return
}

func compareTimes(assert any, utc bool, funk func(time.Time) bool) (result bool) {
	switch tv := assert.(type) {
	case GeneralizedTime:
		result = funk(tv.Cast())
	case UTCTime:
		result = funk(tv.Cast())
	case time.Time:
		result = funk(tv)
	default:
		if utc {
			d, err := marshalUTCTime(tv)
			result = funk(d.Cast()) && err == nil
		} else {
			d, err := marshalGenTime(tv)
			result = funk(d.Cast()) && err == nil
		}
	}

	return
}

func integerMatch(a, b any) (Boolean, error) {
	return integerMatchingRule(a, b, true)
}

func integerOrderingMatch(a, b any) (Boolean, error) {
	return integerMatchingRule(a, b, false)
}

func integerMatchingRule(a, b any, equality bool) (Boolean, error) {
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

	result.Set(compareIntegerInteger(i1, i2, equality))

	return result, nil
}

func compareIntegerInteger(i, tv Integer, equality bool) (is bool) {
	is = i.Cast().Cmp(tv.Cast()) == 0
	if !equality {
		is = i.Cast().Cmp(tv.Cast()) == 0 ||
			i.Cast().Cmp(tv.Cast()) == -1
	}
	return
}

func caseIgnoreMatch(a, b any) (result Boolean, err error) {
	result, err = caseBasedMatch(a, b, false)
	return
}

func caseExactMatch(a, b any) (result Boolean, err error) {
	result, err = caseBasedMatch(a, b, true)
	return
}

func caseBasedMatch(a, b any, caseExact bool) (result Boolean, err error) {
	var str1, str2 string
	str1, err = assertString(a, 1, "string")
	if err != nil {
		return
	}

	str2, err = assertString(b, 1, "string")
	if err != nil {
		return
	}

	if caseExact {
		result.Set(streq(str1, str2))
	} else {
		result.Set(streqf(str1, str2))
	}

	return
}

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

func objectIdentifierMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	// Assertion OID (num or descr)
	if str2, err = assertString(b, 1, "oid"); err != nil {
		return
	}

	// Assertion instance (might not be a string,
	// so allow for other types) ...
	if str1, err = assertString(a, 1, "oid"); err != nil {
		switch tv := a.(type) {
		case Definitions:
			// Try schema Definitions collection
			if idx := tv.Contains(str2); idx != -1 {
				result.Set(true)
				err = nil
			}
		default:
			err = errorBadType("oid")
		}
	} else {
		result.Set(streqf(str1, str2))
	}

	return
}

func directoryStringFirstComponentMatch(a, b any) (result Boolean, err error) {

	// Use reflection to handle the attribute value.
	// This value MUST be a struct (SEQUENCE).
	realValue := assertFirstStructField(a)
	if realValue == nil {
		result.Set(false)
		return
	}

	var field, field2 DirectoryString
	if field, err = marshalDirectoryString(realValue); err != nil {
		result.Set(false)
		return
	}

	if assertValue := assertFirstStructField(b); assertValue == nil {
		field2, err = marshalDirectoryString(b)
	} else {
		field2, err = marshalDirectoryString(assertValue)
	}

	result.Set(streqf(field.String(), field2.String()))

	return
}

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
	// realValue is a DITStructureRuleDescription,
	// as those don't use OIDs.
	if _, ok := a.(DITStructureRuleDescription); ok {
		return
	}

	assertValue := assertFirstStructField(b)
	if assertValue == nil {
		// Try to assert as a string, instead
		str2, _ := assertString(b, 1, "oid")
		var noid NumericOID
		var descr Descriptor

		if noid, err = marshalNumericOID(str2); err == nil {
			assertValue = noid.String()
		} else if descr, err = marshalDescriptor(str2); err == nil {
			assertValue = string(descr)
		}
	}

	if assertField, ok := assertValue.(string); !ok {
		err = errorTxt("first component is not an OID")
	} else {
		result.Set(streqf(field, assertField))
	}

	return
}

/*
for firstComponent matches
*/
func assertFirstStructField(x any) (first any) {
	value := valOf(x)
	if isStruct(x) {
		typ := typeOf(x)
		if typ.NumField() == 0 {
			first = value.Field(0).Interface()
		}
	}

	return
}

func caseExactIA5Match(a, b any) (Boolean, error) {
	return caseBasedIA5Match(a, b, true)
}

func caseIgnoreIA5Match(a, b any) (Boolean, error) {
	return caseBasedIA5Match(a, b, false)
}

func caseBasedIA5Match(a, b any, caseExact bool) (result Boolean, err error) {
	var str1, str2 string
	if str1, err = assertString(a, 1, "ia5String"); err != nil {
		return
	}

	if str2, err = assertString(b, 1, "ia5String"); err != nil {
		return
	}

	result.Set(false)
	if err = checkIA5String(str1); err == nil {
		if err = checkIA5String(str2); err == nil {
			if caseExact {
				result.Set(streq(str1, str2))
			} else {
				result.Set(streqf(str1, str2))
			}
		}
	}

	return
}

func uniqueMemberMatch(a, b any) (result Boolean, err error) {
	var nou1, nou2 NameAndOptionalUID
	if nou1, err = marshalNameAndOptionalUID(a); err != nil {
		return
	}

	if nou2, err = marshalNameAndOptionalUID(b); err != nil {
		return
	}

	if result, err = distinguishedNameMatch(nou1.DN, nou2.DN); err != nil {
		result.Set(false)
		return
	} else if !result.True() {
		return
	}

	if len(nou1.UID.Bytes) == 0 && len(nou2.UID.Bytes) == 0 {
		result.Set(true)
	} else if len(nou1.UID.Bytes) != 0 && len(nou2.UID.Bytes) != 0 {
		var matched Boolean
		matched, err = bitStringMatch(nou1.UID, nou2.UID)
		result.Set(matched)
	}

	return
}

func distinguishedNameMatch(a, b any) (result Boolean, err error) {
	var dn1, dn2 DistinguishedName
	if dn1, err = marshalDistinguishedName(a); err != nil {
		return
	}

	if dn2, err = marshalDistinguishedName(b); err != nil {
		return
	}

	if len(dn1.RDNs) != len(dn2.RDNs) {
		result.Set(false)
		return
	}

	for i := range dn1.RDNs {
		if !dn1.RDNs[i].Equal(dn2.RDNs[i]) {
			result.Set(false)
			return
		}
	}

	result.Set(true)
	return
}

func prepareIA5StringAssertion(a, b any) (str1, str2 string, err error) {
	assertIA5 := func(x any) (i string, err error) {
		var raw string
		if raw, err = assertString(x, 1, "IA5String"); err == nil {
			if err = checkIA5String(raw); err == nil {
				i = raw
			}
		}
		return
	}

	if str1, err = assertIA5(a); err == nil {
		str2, err = assertIA5(b)
	}

	return
}

func prepareStringListAssertion(a, b any) (str1, str2 string, err error) {
	assertSubstringsList := func(x any) (list string, err error) {
		var ok bool
		var slices []string
		if slices, ok = x.([]string); ok {
			list = join(slices, ``)
			list = repAll(list, `\\`, ``)
			list = repAll(list, `$`, ``)
		} else {
			errorBadType("substringslist")
		}
		return
	}

	if str1, err = assertSubstringsList(a); err == nil {
		str2, err = assertSubstringsList(b)
	}

	return
}

// RFC 4518 § 2.6.2
func prepareNumericStringAssertion(a, b any) (str1, str2 string, err error) {
	if str1, err = assertString(a, 0, "numericString"); err != nil {
		return
	}

	if str2, err = assertString(b, 0, "numericString"); err != nil {
		return
	}

	str1 = repAll(str1, ` `, ``)
	str2 = repAll(str2, ` `, ``)

	return
}

// RFC 4518 § 2.6.3
func prepareTelephoneNumberAssertion(a, b any) (str1, str2 string, err error) {
	if str1, err = assertString(a, 0, "numericString"); err != nil {
		return
	}

	if str2, err = assertString(b, 0, "numericString"); err != nil {
		return
	}

	for _, roon := range []rune{
		'\u002d', '\u058a', '\u2010', '\u2011',
		'\u2212', '\ufe63', '\uff0d', '\u0020',
	} {
		str1 = repAll(str1, string(roon), ``)
		str2 = repAll(str2, string(roon), ``)
	}

	return
}

func telephoneNumberMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareTelephoneNumberAssertion(a, b); err == nil {
		result.Set(streqf(str1, str2))
	}

	return
}

func numericStringMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result.Set(streq(str1, str2))
	}

	return
}

func numericStringOrderingMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result.Set(str1 < str2)
	}

	return
}

func caseIgnoreOrderingMatch(a, b any) (Boolean, error) {
	return caseBasedOrderingMatch(a, b, false)
}

func caseExactOrderingMatch(a, b any) (Boolean, error) {
	return caseBasedOrderingMatch(a, b, true)
}

func caseBasedOrderingMatch(a, b any, caseExact bool) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		if caseExact {
			result.Set(str1 < str2)
		} else {
			result.Set(lc(str1) < lc(str2))
		}
	}

	return
}

func caseIgnoreIA5SubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareIA5StringAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}

func telephoneNumberSubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareTelephoneNumberAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}

func numericStringSubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		result, err = caseExactSubstringsMatch(str1, str2)
	}

	return
}

func octetStringOrderingMatch(a, b any) (result Boolean, err error) {
	var str1, str2 []byte

	if str1, err = assertOctetString(a); err != nil {
		return
	}

	if str2, err = assertOctetString(b); err != nil {
		return
	}

	mLen := len(str2)
	if len(str1) < mLen {
		mLen = len(str1)
	}

	// Compare octet strings from the first octet to the last
	for i := 0; i < mLen; i++ {
		if str2[i] < str1[i] {
			result.Set(true)
			return
		} else if str2[i] > str1[i] {
			result.Set(false)
			return
		}
	}

	// If the strings are identical up to the length of the
	// shorter string, the shorter string precedes the longer
	// string
	result.Set(len(str2) < len(str1))
	return
}

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

func caseIgnoreListSubstringsMatch(a, b any) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareStringListAssertion(a, b); err == nil {
		result, err = caseIgnoreSubstringsMatch(str1, str2)
	}

	return
}
