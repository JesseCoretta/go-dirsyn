package dirsyn

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
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
	erris      func(error, error) bool                   = errors.Is
	mkerr      func(string) error                        = errors.New
	fields     func(string) []string                     = strings.Fields
	bfields    func([]byte) [][]byte                     = bytes.Fields
	trimS      func(string) string                       = strings.TrimSpace
	trimL      func(string, string) string               = strings.TrimLeft
	trimR      func(string, string) string               = strings.TrimRight
	trimPfx    func(string, string) string               = strings.TrimPrefix
	trimSfx    func(string, string) string               = strings.TrimSuffix
	btrimL     func([]byte, string) []byte               = bytes.TrimLeft
	btrimR     func([]byte, string) []byte               = bytes.TrimRight
	btrimS     func([]byte) []byte                       = bytes.TrimSpace
	hasPfx     func(string, string) bool                 = strings.HasPrefix
	hasSfx     func(string, string) bool                 = strings.HasSuffix
	bhasPfx    func([]byte, []byte) bool                 = bytes.HasPrefix
	bhasSfx    func([]byte, []byte) bool                 = bytes.HasSuffix
	join       func([]string, string) string             = strings.Join
	bsplit     func([]byte, []byte) [][]byte             = bytes.Split
	split      func(string, string) []string             = strings.Split
	splitN     func(string, string, int) []string        = strings.SplitN
	stridx     func(string, string) int                  = strings.Index
	lstridx    func(string, string) int                  = strings.LastIndex
	idxany     func(string, string) int                  = strings.IndexAny
	idxr       func(string, rune) int                    = strings.IndexRune
	repAll     func(string, string, string) string       = strings.ReplaceAll
	brepAll    func([]byte, []byte, []byte) []byte       = bytes.ReplaceAll
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
	bidx       func([]byte, []byte) int                  = bytes.Index
	strlidx    func(string, string) int                  = strings.LastIndex
	strcnt     func(string, string) int                  = strings.Count
	trim       func(string, string) string               = strings.Trim
	uc         func(string) string                       = strings.ToUpper
	lc         func(string) string                       = strings.ToLower
	blc        func([]byte) []byte                       = bytes.ToLower
	buc        func([]byte) []byte                       = bytes.ToUpper
	readFile   func(string) ([]byte, error)              = os.ReadFile
	ostat      func(string) (os.FileInfo, error)         = os.Stat
	newBigInt  func(int64) *big.Int                      = big.NewInt
	valOf      func(any) reflect.Value                   = reflect.ValueOf
	typeOf     func(any) reflect.Type                    = reflect.TypeOf
	regexMatch func(string, string) (bool, error)        = regexp.MatchString
	now        func() time.Time                          = time.Now
	uint16g    func([]byte) uint16                       = binary.BigEndian.Uint16
	uint16p    func([]byte, uint16)                      = binary.BigEndian.PutUint16
)

/*
getStringer uses reflect to obtain and return a given
type instance's String ("stringer") method, if present.
If not, nil is returned.
*/
func getStringer(x any) (meth func() string) {
	if x != nil {
		if v := valOf(x); !v.IsZero() {
			if method := v.MethodByName(`String`); method.Kind() != reflect.Invalid {
				if _meth, ok := method.Interface().(func() string); ok {
					meth = _meth
				}
			}
		}
	}

	return
}

func removeWHSP(a string) string {
	return repAll(a, ` `, ``)
}

func streq(a, b string) bool {
	return a == b
}

func removeBashComments(input []byte) (output []byte) {
	stripComments := func(line string) string {
		re := regexp.MustCompile("#.*")
		return re.ReplaceAllString(line, "")
	}

	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		line := scanner.Text()
		strippedLine := stripComments(line)
		if len(strippedLine) > 0 {
			output = append(output, []byte(strippedLine+"\n")...)
		}
	}

	return
}

/*
isAttribute returns a boolean value indicative of whether val
describes a numeric OID or RFC 4512 descriptor ("descr").

This is used, specifically, it identify an schema definition's
"NAME" or specify any number of values for an ACIAttribute.
*/
func isAttribute(val string) (is bool) {
	_, err := marshalNumericOID(val)
	if is = err == nil; !is {
		is = isAttributeDescriptor(val)
	}

	return
}

/*
isAttributeDescriptor scans the input string val and judges
whether it appears to qualify as a valid RFC 4512 descriptor
(or "descr"), in that:

  - it begins with an alpha
  - it ends with an alpha or digit
  - it contains only alphas, digits, hyphens or semicolons
  - it contains no consecutive hyphens or semicolons
*/
func isAttributeDescriptor(val string) bool {
	if len(val) == 0 {
		return false
	}

	// must begin with an alpha.
	if !isAlpha(rune(val[0])) {
		return false
	}

	// can only end in alnum.
	if !isAlnum(rune(val[len(val)-1])) {
		return false
	}

	for i := 0; i < len(val); i++ {
		ch := rune(val[i])
		switch {
		case isAlnum(ch):
			// ok
		case ch == ';', ch == '-':
			// ok
		default:
			return false
		}
	}

	return true
}

/*
assertFirstStructField is a private function used for
firstComponent EQUALITY matching, in which the first
struct (ASN.1 SEQUENCE) field is matched.
*/
func assertFirstStructField(x any) (first any) {
	if isStruct(x) {
		if typ := typeOf(x); typ.NumField() > 0 {
			first = valOf(x).Field(0).Interface()
		}
	}

	return
}

/*
isStruct is a private function which returns a Boolean
value indicative of whether kind reflection revealed
the presence of a struct type.
*/
func isStruct(x any) (is bool) {
	if x != nil {
		is = typeOf(x).Kind() == reflect.Struct
	}

	return
}

/*
newStrBuilder is a private function which returns an
instance of strings.Builder. This is merely a convenience
wrapper which avoids the need for multiple import calls
of the bytes package.
*/
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

/*
isBase64 is a private function which returns a Boolean
value indicative of whether input x -- which must be an
instance of string or []byte -- is a base64 encoded
value.
*/
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

/*
b64dec is a private function which returns an instance of []byte
alongside an error. The return []byte instance represents the base64
decoded value of enc.
*/
func b64dec(enc []byte) (dec []byte, err error) {
	dec = make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
	_, err = base64.StdEncoding.Decode(dec, enc)
	return
}

/*
splitUnescaped returns an instance of []string based upon an attempt
to split the input str value on separator characters which are NOT
escaped. Escaped separator values are ignored.

For example, this allows a string to be split on comma (,) while
ignoring escaped commas (\,).
*/
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

/*
strInSlice returns a Boolean value indicative of the presence of
r within the input slice value.  The optional variadic input value
cEM indicates whether the matching process should recognize exact
case folding.

By default, case is not significant in the matching process.
*/
func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := streqf
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch
			funk = streq
		}
	}

	switch tv := r.(type) {
	case string:
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(tv, slice[i])
		}
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			for j := 0; j < len(slice) && !match; j++ {
				match = funk(tv[i], slice[j])
			}
		}
	}

	return
}

/*
isUnsignedNumber is a private function which returns a Boolean
value indicative of whether input x is an unsigned (non-negative)
decimal number in string representation.
*/
func isUnsignedNumber(x string) bool {
	return isNumber(x) && !hasPfx(x, `-`)
}

/*
isNumber is a private function which returns a Boolean value
indicative of whether input x represents any signed or unsigned
decimal number in string representation.
*/
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

func caseIgnoreOrderingMatch(a, b any, operator byte) (Boolean, error) {
	return caseBasedOrderingMatch(a, b, false, operator)
}

func caseExactOrderingMatch(a, b any, operator byte) (Boolean, error) {
	return caseBasedOrderingMatch(a, b, true, operator)
}

func caseBasedOrderingMatch(a, b any, caseExact bool, operator byte) (result Boolean, err error) {
	var str1, str2 string
	if str1, str2, err = prepareNumericStringAssertion(a, b); err == nil {
		if caseExact {
			if operator == GreaterOrEqual {
				result.Set(str1 >= str2)
			} else {
				result.Set(str2 <= str1)
			}
		} else {
			if operator == GreaterOrEqual {
				result.Set(lc(str1) >= lc(str2))
			} else {
				result.Set(lc(str2) <= lc(str1))
			}
		}
	}

	return
}

/*
condenseWHSP returns input as a string with all contiguous
WHSP characters condensed into single space characters.

The input value may be a string or []byte instance.

WHSP is qualified through space or TAB chars (ASCII #32
and #9 respectively).
*/
func condenseWHSP(input any) (a string) {
	// remove leading and trailing
	// WHSP characters ...
	var b string
	switch tv := input.(type) {
	case string:
		b = tv
	case []byte:
		b = string(tv)
	default:
		return ``
	}

	b = trimS(b)
	b = repAll(b, string(rune(10)), string(rune(32)))

	var last bool
	for i := 0; i < len(b); i++ {
		c := rune(b[i])
		switch c {
		// match space (32) or tab (9)
		case rune(9), rune(10), rune(32):
			if !last {
				last = true
				a += string(rune(32))
			}
		default:
			if last {
				last = false
			}
			a += string(c)
		}
	}

	a = trimS(a)
	return
}

/*
isPtr returns a Boolean value indicative of whether kind
reflection revealed the presence of a pointer type.
*/
func isPtr(x any) bool {
	return typeOf(x).Kind() == reflect.Ptr
}

/*
isIUint returns a Boolean value of true if x represents a
member of the integer / unsigned integer "family". Any size
is allowed, so long as it is a built-in primitive.

If a (valid) member is a pointer reference, it is dereferenced
and examined just the same.

Floats and complexes are ineligible and will return false as they
are not used in this package. Additionally, non-numerical types
shall return false. This would include structs, strings, maps, etc.
*/
func isIUint(x any) (is bool) {
	// create a reflect.Type abstract
	// instance using raw input x.
	X := typeOf(x)

	// disenvelop the instance if
	// it is a pointer reference.
	if isPtr(x) {
		X = X.Elem()
	}

	// perform a reflect.Kind switch upon
	// reflect.Type instance X ...
	switch k := X.Kind(); k {

	// allow only the following "kinds":
	case reflect.Int, reflect.Uint,
		reflect.Int8, reflect.Uint8,
		reflect.Int16, reflect.Uint16,
		reflect.Int32, reflect.Uint32,
		reflect.Int64, reflect.Uint64,
		reflect.Uintptr:
		is = true
	}

	return
}

/*
getBitSize returns the max bit length capacity
for a given type.

Note this will only return a meaningful value if
x represents a numerical type, such as Day, Right
or Level (all of which are subject to bit shifts).
Passing inappropriate type instances, such as a
struct, string, etc., will return zero (0).

This function uses the reflect.Size method (and
thus unsafe.Sizeof) to obtain a uintptr, which
will be cast as an int, multiplied by eight (8)
and finally returned.
*/
func bitSize(x any) (bits int) {
	if x == nil {
		return
	}

	// create a reflect.Type abstract
	// instance using raw input x.
	X := typeOf(x)

	// disenvelop the instance if
	// it is a pointer reference.
	if isPtr(x) {
		X = X.Elem()
	}

	// see if the instance is an int
	// or uint (or a variant of same)
	if isIUint(x) {
		bits = int(X.Size()) * 8
	}

	return
}

// percentDecode manually decodes percent-encoded sequences in a string.
// For every '%' followed by two valid hexadecimal digits, the sequence is replaced by the corresponding byte.
func percentDecode(s string) (dec string, err error) {
	result := newStrBuilder()

	for i := 0; i < len(s); {
		if s[i] == '%' {
			if i+2 >= len(s) {
				err = errorTxt("invalid percent encoding: incomplete sequence")
				break
			}

			hexDigits := s[i+1 : i+3]
			var num uint64
			if num, err = puint(hexDigits, 16, 8); err != nil {
				err = errorTxt("invalid percent encoding \"" + hexDigits + "\": " + err.Error())
				break
			}

			result.WriteByte(byte(num))
			i += 3
		} else {
			result.WriteByte(s[i])
			i++
		}
	}

	if err == nil {
		dec = result.String()
	}

	return
}

// splitAndTrim splits a string by the given separator and trims spaces from each slice element.
func splitAndTrim(s, sep string) []string {
	raw := split(s, sep)
	var parts []string
	for _, part := range raw {
		if trimmed := trimS(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

/*
LDAPString implements [§ 4.1.2 of RFC 4511].

[§ 4.1.2 of RFC 4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.2
*/
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
	`1.3.6.1.1.16.1`:                uUID,
}

/*
EqualityRuleAssertion defines a closure signature held by qualifying
function instances intended to implement an Equality MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type EqualityRuleAssertion func(any, any) (Boolean, error)

func (r EqualityRuleAssertion) isMatchingRuleAssertionFunction() {}
func (r EqualityRuleAssertion) kind() string                     { return `EQUALITY` }

/*
SubstringsRuleAssertion defines a closure signature held by qualifying
function instances intended to implement a Substrings MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type SubstringsRuleAssertion func(any, any) (Boolean, error)

func (r SubstringsRuleAssertion) isMatchingRuleAssertionFunction() {}
func (r SubstringsRuleAssertion) kind() string                     { return `SUBSTR` }

/*
OrderingRuleAssertion defines a closure signature held by qualifying
function instances intended to implement an Ordering MatchingRuleAssertion.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type OrderingRuleAssertion func(any, any, byte) (Boolean, error)

func (r OrderingRuleAssertion) isMatchingRuleAssertionFunction() {}
func (r OrderingRuleAssertion) kind() string                     { return `ORDERING` }

/*
matchingRuleAssertion is a private interface type which is qualified
through instances of EqualityRuleAssertion, SubstringsRuleAssertion
and OrderingRuleAssertion closure functions.
*/
type matchingRuleAssertion interface {
	// kind returns the string literal
	// EQUALITY, SUBSTR or ORDERING.
	kind() string

	// Differentiate from other interfaces
	isMatchingRuleAssertionFunction()
}

/*
GreaterOrEqual (>=), when input to an [OrderingRuleAssertion] function,
results in a greater or equal (GE) comparison.
*/
const GreaterOrEqual byte = 0x0

/*
LessOrEqual (<=), when input to an [OrderingRuleAssertion] function,
results in a less or equal (LE) comparison.
*/
const LessOrEqual byte = 0x1

var matchingRuleAssertions map[string]matchingRuleAssertion = map[string]matchingRuleAssertion{
	"2.5.13.0":                   EqualityRuleAssertion(objectIdentifierMatch),
	"2.5.13.1":                   EqualityRuleAssertion(distinguishedNameMatch),
	"2.5.13.2":                   EqualityRuleAssertion(caseIgnoreMatch),
	"2.5.13.3":                   OrderingRuleAssertion(caseIgnoreOrderingMatch),
	"2.5.13.4":                   SubstringsRuleAssertion(caseIgnoreSubstringsMatch),
	"2.5.13.5":                   EqualityRuleAssertion(caseExactMatch),
	"2.5.13.6":                   OrderingRuleAssertion(caseExactOrderingMatch),
	"2.5.13.7":                   SubstringsRuleAssertion(caseExactSubstringsMatch),
	"2.5.13.8":                   EqualityRuleAssertion(numericStringMatch),
	"2.5.13.9":                   OrderingRuleAssertion(numericStringOrderingMatch),
	"2.5.13.10":                  SubstringsRuleAssertion(numericStringSubstringsMatch),
	"2.5.13.11":                  EqualityRuleAssertion(caseIgnoreListMatch),
	"2.5.13.12":                  SubstringsRuleAssertion(caseIgnoreListSubstringsMatch),
	"2.5.13.13":                  EqualityRuleAssertion(booleanMatch),
	"2.5.13.14":                  EqualityRuleAssertion(integerMatch),
	"2.5.13.15":                  OrderingRuleAssertion(integerOrderingMatch),
	"2.5.13.16":                  EqualityRuleAssertion(bitStringMatch),
	"2.5.13.17":                  EqualityRuleAssertion(octetStringMatch),
	"2.5.13.18":                  OrderingRuleAssertion(octetStringOrderingMatch),
	"2.5.13.20":                  EqualityRuleAssertion(telephoneNumberMatch),
	"2.5.13.21":                  SubstringsRuleAssertion(telephoneNumberSubstringsMatch),
	"2.5.13.23":                  EqualityRuleAssertion(uniqueMemberMatch),
	"2.5.13.27":                  EqualityRuleAssertion(generalizedTimeMatch),
	"2.5.13.28":                  OrderingRuleAssertion(generalizedTimeOrderingMatch),
	"2.5.13.29":                  EqualityRuleAssertion(integerFirstComponentMatch),
	"2.5.13.30":                  EqualityRuleAssertion(objectIdentifierFirstComponentMatch),
	"2.5.13.31":                  EqualityRuleAssertion(directoryStringFirstComponentMatch),
	"2.5.13.32":                  EqualityRuleAssertion(wordMatch),
	"2.5.13.33":                  EqualityRuleAssertion(keywordMatch),
	"1.3.6.1.4.1.1466.109.114.1": EqualityRuleAssertion(caseExactIA5Match),
	"1.3.6.1.4.1.1466.109.114.2": EqualityRuleAssertion(caseIgnoreIA5Match),
	"1.3.6.1.4.1.1466.109.114.3": SubstringsRuleAssertion(caseIgnoreIA5SubstringsMatch),
	"1.3.6.1.1.16.2":             EqualityRuleAssertion(uuidMatch),
	"1.3.6.1.1.16.3":             OrderingRuleAssertion(uuidOrderingMatch),
}
