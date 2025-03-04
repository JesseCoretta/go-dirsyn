package dirsyn

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	fmtInt     func(int64, int) string                   = strconv.FormatInt
	fmtUint    func(uint64, int) string                  = strconv.FormatUint
	atoi       func(string) (int, error)                 = strconv.Atoi
	itoa       func(int) string                          = strconv.Itoa
	cntns      func(string, string) bool                 = strings.Contains
	mkerr      func(string) error                        = errors.New
	fields     func(string) []string                     = strings.Fields
	trimS      func(string) string                       = strings.TrimSpace
	trimL      func(string, string) string               = strings.TrimLeft
	trimR      func(string, string) string               = strings.TrimRight
	trimPfx    func(string, string) string               = strings.TrimPrefix
	trimSfx    func(string, string) string               = strings.TrimSuffix
	hasPfx     func(string, string) bool                 = strings.HasPrefix
	hasSfx     func(string, string) bool                 = strings.HasSuffix
	join       func([]string, string) string             = strings.Join
	split      func(string, string) []string             = strings.Split
	splitN     func(string, string, int) []string        = strings.SplitN
	idxr       func(string, rune) int                    = strings.IndexRune
	repAll     func(string, string, string) string       = strings.ReplaceAll
	puint      func(string, int, int) (uint64, error)    = strconv.ParseUint
	fuint      func(uint64, int) string                  = strconv.FormatUint
	hexdec     func(string) ([]byte, error)              = hex.DecodeString
	hexencs    func([]byte) string                       = hex.EncodeToString
	hexlen     func(int) int                             = hex.EncodedLen
	hexenc     func([]byte, []byte) int                  = hex.Encode
	asn1m      func(any) ([]byte, error)                 = asn1.Marshal
	asn1mp     func(any, string) ([]byte, error)         = asn1.MarshalWithParams
	asn1um     func([]byte, any) ([]byte, error)         = asn1.Unmarshal
	asn1ump    func([]byte, any, string) ([]byte, error) = asn1.UnmarshalWithParams
	streqf     func(string, string) bool                 = strings.EqualFold
	stridx     func(string, string) int                  = strings.Index
	strlidx    func(string, string) int                  = strings.LastIndex
	strcnt     func(string, string) int                  = strings.Count
	trim       func(string, string) string               = strings.Trim
	uc         func(string) string                       = strings.ToUpper
	lc         func(string) string                       = strings.ToLower
	readFile   func(string) ([]byte, error)              = os.ReadFile
	newBigInt  func(int64) *big.Int                      = big.NewInt
	valOf      func(any) reflect.Value                   = reflect.ValueOf
	typeOf     func(any) reflect.Type                    = reflect.TypeOf
	regexMatch func(string, string) (bool, error)        = regexp.MatchString
	now        func() time.Time                          = time.Now
)

func removeWHSP(a string) string {
	return repAll(a, ` `, ``)
}

func streq(a, b string) bool {
	return a == b
}

/*
for firstComponent matches
*/
func assertFirstStructField(x any) (first any) {
	value := valOf(x)
	if isStruct(x) {
		typ := typeOf(x)
		if typ.NumField() > 0 {
			first = value.Field(0).Interface()
		}
	}

	return
}

/*
isStruct returns a boolean value indicative of whether
kind reflection revealed the presence of a struct type.
*/
func isStruct(x any) (is bool) {
	if x != nil {
		is = typeOf(x).Kind() == reflect.Struct
	}

	return
}

func newStrBuilder() strings.Builder {
	return strings.Builder{}
}

func escapeString(x string) (esc string) {
	if len(x) > 0 {
		bld := newStrBuilder()
		for _, z := range x {
			if z > maxASCII {
				for _, c := range []byte(string(z)) {
					bld.WriteString(`\`)
					bld.WriteString(fuint(uint64(c), 16))
				}
			} else {
				bld.WriteRune(z)
			}
		}

		esc = bld.String()
	}

	return
}

func uitoa(x any) (s string) {
        switch tv := x.(type) {
        case uint:
                s = strconv.FormatUint(uint64(tv), 10)
        case uint64:
                s = strconv.FormatUint(tv, 10)
        }

        return
}

func hexEncode(x any) string {
	var r string
	switch tv := x.(type) {
	case string:
		r = tv
	case []byte:
		r = string(tv)
	default:
		return ``
	}

	e := newStrBuilder()
	for _, c := range r {
		for _, b := range []byte(string(c)) {
			e.WriteString("\\")
			e.WriteString(fuint(uint64(b), 16))
		}
	}
	return e.String()
}

func hexDecode(x any) string {
	var r string
	switch tv := x.(type) {
	case string:
		r = tv
	case []byte:
		r = string(tv)
	default:
		return ``
	}

	d := newStrBuilder()
	length := len(r)

	for i := 0; i < length; i++ {
		if r[i] == '\\' && i+3 <= length {
			b, err := hexdec(r[i+1 : i+3])
			if err != nil || !(isHex(rune(r[i+1])) || isHex(rune(r[i+2]))) {
				return ``
			}
			d.Write(b)
			i += 2
		} else {
			d.WriteString(string(r[i]))
		}
	}

	return d.String()
}

func isBase64(x any) (is bool) {
	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	default:
		return
	}

	_, err := base64.StdEncoding.DecodeString(raw)
	is = err == nil

	return
}

func b64dec(enc []byte) (dec []byte, err error) {
	dec = make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
	_, err = base64.StdEncoding.Decode(dec, enc)
	return
}

func splitUnescaped(str, sep, esc string) (slice []string) {
	slice = split(str, sep)
	for i := len(slice) - 2; i >= 0; i-- {
		if hasSfx(slice[i], esc) {
			slice[i] = slice[i][:len(slice[i])-len(esc)] + sep + slice[i+1]
			slice = append(slice[:i+1], slice[i+2:]...)
		}
	}

	return
}

func strInSlice(r string, slice []string, cEM ...bool) (match bool) {
	var cem bool
	if len(cEM) > 0 {
		cem = cEM[0]
	}

	for i := 0; i < len(slice) && !match; i++ {
		if cem {
			match = r == slice[i]
		} else {
			match = streqf(r, slice[i])
		}
	}

	return
}

func isUnsignedNumber(x string) bool {
	return isNumber(x) && !hasPfx(x, `-`)
}

func isNumber(x string) bool {
	x = trimL(x, `-`)
	for _, c := range x {
		if !('0' <= rune(c) && rune(c) <= '9') {
			return false
		}
	}

	return true
}

func assertString(x any, min int, name string) (str string, err error) {
	switch tv := x.(type) {
	case []byte:
		str, err = assertString(string(tv), min, name)
	case string:
		if len(tv) < min && min != 0 {
			err = errorBadLength(name, 0)
			break
		}
		str = tv
	default:
		err = errorBadType(name)
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

type LDAPString OctetString

/*
SyntaxVerification implements a closure function signature meant to be
honored by functions or methods intended to verify the syntax of a value.
*/
type SyntaxVerification func(any) Boolean

var syntaxVerifiers map[string]SyntaxVerification = map[string]SyntaxVerification{
	`1.3.6.1.4.1.1466.115.121.1.3`:  attributeTypeDescription,
	`1.3.6.1.4.1.1466.115.121.1.6`:  bitString,
	`1.3.6.1.4.1.1466.115.121.1.7`:  boolean,
	`1.3.6.1.4.1.1466.115.121.1.11`: countryString,
	`1.3.6.1.4.1.1466.115.121.1.14`: deliveryMethod,
	`1.3.6.1.4.1.1466.115.121.1.15`: directoryString,
	`1.3.6.1.4.1.1466.115.121.1.16`: dITContentRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.17`: dITStructureRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.12`: dN,
	`1.3.6.1.4.1.1466.115.121.1.21`: enhancedGuide,
	`1.3.6.1.4.1.1466.115.121.1.22`: facsimileTelephoneNumber,
	`1.3.6.1.4.1.1466.115.121.1.23`: fax,
	`1.3.6.1.4.1.1466.115.121.1.24`: generalizedTime,
	`1.3.6.1.4.1.1466.115.121.1.25`: guide,
	`1.3.6.1.4.1.1466.115.121.1.26`: iA5String,
	`1.3.6.1.4.1.1466.115.121.1.27`: integer,
	`1.3.6.1.4.1.1466.115.121.1.28`: jPEG,
	`1.3.6.1.4.1.1466.115.121.1.54`: lDAPSyntaxDescription,
	`1.3.6.1.4.1.1466.115.121.1.30`: matchingRuleDescription,
	`1.3.6.1.4.1.1466.115.121.1.31`: matchingRuleUseDescription,
	`1.3.6.1.4.1.1466.115.121.1.34`: nameAndOptionalUID,
	`1.3.6.1.4.1.1466.115.121.1.35`: nameFormDescription,
	`1.3.6.1.4.1.1466.115.121.1.36`: numericString,
	`1.3.6.1.4.1.1466.115.121.1.37`: objectClassDescription,
	`1.3.6.1.4.1.1466.115.121.1.40`: octetString,
	`1.3.6.1.4.1.1466.115.121.1.38`: oID,
	`1.3.6.1.4.1.1466.115.121.1.39`: otherMailbox,
	`1.3.6.1.4.1.1466.115.121.1.41`: postalAddress,
	`1.3.6.1.4.1.1466.115.121.1.44`: printableString,
	`1.3.6.1.4.1.1466.115.121.1.58`: substringAssertion,
	`1.3.6.1.4.1.1466.115.121.1.50`: telephoneNumber,
	`1.3.6.1.4.1.1466.115.121.1.51`: teletexTerminalIdentifier,
	`1.3.6.1.4.1.1466.115.121.1.52`: telexNumber,
	`1.3.6.1.4.1.1466.115.121.1.53`: uTCTime,
}

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
