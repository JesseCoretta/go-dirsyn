package dirsyn

/*
dn.go contains DN, RDN and ATV syntax verifiers.  Note that the bulk of
this file is derived from the most excellent go-ldap (v3) package.

From https://github.com/go-ldap/ldap/blob/master/LICENSE:

The MIT License (MIT)

Copyright (c) 2011-2015 Michael Mitton (mmitton@gmail.com)
Portions copyright (c) 2015-2016 go-ldap Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

See also the go-ldap.LICENSE file in the repository root.
*/

import (
	"encoding/hex"
	"sort"

	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
AttributeTypeAndValue implements the attributeTypeAndValue defined in
[Section 3 of RFC4514].

[Section 3 of RFC4514]: https://datatracker.ietf.org/doc/html/rfc4514#section-3
*/
type AttributeTypeAndValue struct {
	// Type is the attribute type
	Type string
	// Value is the attribute value
	Value string
}

func (r *AttributeTypeAndValue) setType(str string) error {
	result, err := decodeString(str)
	if err != nil {
		return err
	}
	r.Type = result

	return nil
}

func (r *AttributeTypeAndValue) setValue(s string) error {
	// https://www.ietf.org/rfc/rfc4514.html#section-2.4
	// If the AttributeType is of the dotted-decimal form, the
	// AttributeValue is represented by an number sign ('#' U+0023)
	// character followed by the hexadecimal encoding of each of the octets
	// of the BER encoding of the X.500 AttributeValue.
	if len(s) > 0 && s[0] == '#' {
		decodedString, err := decodeEncodedString(s[1:])
		if err != nil {
			return err
		}

		r.Value = decodedString
		return nil
	} else {
		decodedString, err := decodeString(s)
		if err != nil {
			return err
		}

		r.Value = decodedString
		return nil
	}
}

/*
String returns a normalized string representation of this attribute type
and value pair which is the lowercase join of the Type and Value with a "=".
*/
func (r *AttributeTypeAndValue) String() string {
	return encodeString(foldString(r.Type), false) + "=" + encodeString(r.Value, true)
}

/*
RelativeDistinguishedName implements the relativeDistinguishedName defined
in [Section 3 of RFC4514].

[Section 3 of RFC4514]: https://datatracker.ietf.org/doc/html/rfc4514#section-3
*/
type RelativeDistinguishedName struct {
	Attributes []*AttributeTypeAndValue
}

/*
String returns a normalized string representation of this relative
distinguishedName which is the join of all attributes (sorted in
increasing order) with a "+".
*/
func (r *RelativeDistinguishedName) String() string {
	attrs := make([]string, len(r.Attributes))
	for i := range r.Attributes {
		attrs[i] = r.Attributes[i].String()
	}
	sort.Strings(attrs)
	return join(attrs, "+")
}

/*
DistinguishedName implements the distinguished name from RFC4514 and RFC4517.
*/
type DistinguishedName struct {
	RDNs []*RelativeDistinguishedName
}

// String returns a normalized string representation of this distinguishedName which is the
// join of all relative distinguishedNames with a ",".
func (r *DistinguishedName) String() string {
	rdns := make([]string, len(r.RDNs))
	for i := range r.RDNs {
		rdns[i] = r.RDNs[i].String()
	}
	return join(rdns, ",")
}

func stripLeadingAndTrailingSpaces(inVal string) string {
	noSpaces := trim(inVal, " ")

	// Re-add the trailing space if it was an escaped space
	if len(noSpaces) > 0 && noSpaces[len(noSpaces)-1] == '\\' &&
		inVal[len(inVal)-1] == ' ' {
		noSpaces = noSpaces + " "
	}

	return noSpaces
}

// Remove leading and trailing spaces from the attribute type and value
// and unescape any escaped characters in these fields
//
// decodeString is based on https://github.com/inteon/cert-manager/blob/ed280d28cd02b262c5db46054d88e70ab518299c/pkg/util/pki/internal/dn.go#L170
func decodeString(str string) (string, error) {
	s := []rune(stripLeadingAndTrailingSpaces(str))

	builder := newStrBuilder()
	for i := 0; i < len(s); i++ {
		char := s[i]

		// If the character is not an escape character, just add it to the
		// builder and continue
		if char != '\\' {
			builder.WriteRune(char)
			continue
		}

		// If the escape character is the last character, it's a corrupted
		// escaped character
		if i+1 >= len(s) {
			return "", errorTxt("got corrupted escaped character: " + string(s))
		}

		// If the escaped character is a special character, just add it to
		// the builder and continue
		switch s[i+1] {
		case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
			builder.WriteRune(s[i+1])
			i++
			continue
		}

		// If the escaped character is not a special character, it should
		// be a hex-encoded character of the form \XX if it's not at least
		// two characters long, it's a corrupted escaped character
		if i+2 >= len(s) {
			return "", errorTxt("failed to decode escaped character: encoding/hex: invalid byte: " +
				string(s[i+1]))
		}

		// Get the runes for the two characters after the escape character
		// and convert them to a byte slice
		xx := []byte(string(s[i+1 : i+3]))

		// If the two runes are not hex characters and result in more than
		// two bytes when converted to a byte slice, it's a corrupted
		// escaped character
		if len(xx) != 2 {
			return "", errorTxt("failed to decode escaped character: invalid byte: " + string(xx))
		}

		// Decode the hex-encoded character and add it to the builder
		dst := []byte{0}
		if n, err := hex.Decode(dst, xx); err != nil {
			return "", errorTxt("failed to decode escaped character: " + err.Error())
		} else if n != 1 {
			return "", errorTxt("failed to decode escaped character: encoding/hex: expected 1 byte when un-escaping, got " + fmtInt(int64(n), 10))
		}

		builder.WriteByte(dst[0])
		i += 2
	}

	return builder.String(), nil
}

// Escape a string according to RFC 4514
func encodeString(value string, isValue bool) string {
	builder := newStrBuilder()

	escapeChar := func(c byte) {
		builder.WriteByte('\\')
		builder.WriteByte(c)
	}

	escapeHex := func(c byte) {
		builder.WriteByte('\\')
		builder.WriteString(hex.EncodeToString([]byte{c}))
	}

	// Loop through each byte and escape as necessary.
	// Runes that take up more than one byte are escaped
	// byte by byte (since both bytes are non-ASCII).
	for i := 0; i < len(value); i++ {
		char := value[i]
		if i == 0 && (char == ' ' || char == '#') {
			// Special case leading space or number sign.
			escapeChar(char)
			continue
		}
		if i == len(value)-1 && char == ' ' {
			// Special case trailing space.
			escapeChar(char)
			continue
		}

		switch char {
		case '"', '+', ',', ';', '<', '>', '\\':
			// Each of these special characters must be escaped.
			escapeChar(char)
			continue
		}

		if !isValue && char == '=' {
			// Equal signs have to be escaped only in the type part of
			// the attribute type and value pair.
			escapeChar(char)
			continue
		}

		if char < ' ' || char > '~' {
			// All special character escapes are handled first
			// above. All bytes less than ASCII SPACE and all bytes
			// greater than ASCII TILDE must be hex-escaped.
			escapeHex(char)
			continue
		}

		// Any other character does not require escaping.
		builder.WriteByte(char)
	}

	return builder.String()
}

func decodeEncodedString(str string) (string, error) {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		return "", errorTxt("failed to decode BER encoding: " + err.Error())
	}

	packet, err := ber.DecodePacketErr(decoded)
	if err != nil {
		return "", errorTxt("failed to decode BER encoding: " + err.Error())
	}

	return packet.Data.String(), nil
}

/*
DistinguishedName returns an error following an analysis of x in the
context of a distinguished name.

Note: DN, RDN and ATV parsing capabilities derived from [go-ldap/ldap/v3/dn.go]

From [§ 3 of RFC 4514]:

	distinguishedName = [ relativeDistinguishedName *( COMMA relativeDistinguishedName ) ]
	relativeDistinguishedName = attributeTypeAndValue *( PLUS attributeTypeAndValue )
	attributeTypeAndValue = attributeType EQUALS attributeValue
	attributeType = descr / numericoid
	attributeValue = string / hexstring
	string = [ ( leadchar / pair ) [ *( stringchar / pair ) ( trailchar / pair ) ] ]

	leadchar = LUTF1 / UTFMB
	LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F

	trailchar  = TUTF1 / UTFMB
	TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F

	stringchar = SUTF1 / UTFMB
	SUTF1 = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F

	pair = ESC ( ESC / special / hexpair )
	special = escaped / SPACE / SHARP / EQUALS
	escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
	hexstring = SHARP 1*hexpair
	hexpair = HEX HEX

[§ 3 of RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514#section-3
[go-ldap/ldap/v3/dn.go]: https://github.com/go-ldap/ldap/blob/master/dn.go
*/
func (r RFC4514) DistinguishedName(x any) (dn *DistinguishedName, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			// technically fine.
			return
		}
		raw = tv
	case []byte:
		dn, err = r.DistinguishedName(string(tv))
		return
	default:
		err = errorBadType("Distinguished Name")
		return
	}

	dn, err = parseDN(raw)

	return
}

/*
DistinguishedName is a wrapping alias for [RFC4514.DN].
*/
func (r RFC4517) DistinguishedName(x any) (dn *DistinguishedName, err error) {
	var s RFC4514
	dn, err = s.DistinguishedName(x)
	return
}

/*
NameAndOptionalUID returns an error following an analysis of x in the
context of a Name and Optional UID.

From [§ 3.3.21 of RFC 4517]:

	NameAndOptionalUID = distinguishedName [ SHARP BitString ]

From [§ 3.3.2 of RFC 4517]:

	BitString    = SQUOTE *binary-digit SQUOTE "B"
	binary-digit = "0" / "1"

From [§ 1.4 of RFC 4512]:

	SHARP  = %x23	; octothorpe (or sharp sign) ("#")
	SQUOTE = %x27	; single quote ("'")

[§ 3.3.21 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21
[§ 3.3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NameAndOptionalUID struct {
	DN  DistinguishedName
	UID BitString `asn1:"optional"`
}

/*
NameAndOptionalUID returns an instance of [NameAndOptionalUID] alongside
an error.
*/
func (r RFC4517) NameAndOptionalUID(x any) (nou NameAndOptionalUID, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Name and Optional UID"); err != nil {
		return
	}

	var rev string
	for i := 0; i < len(raw); i++ {
		rev += string(raw[len(raw)-i-1])
	}

	var _l int = len(raw)
	if hasPfx(rev, `B'`) {
		var bitstring string = `'`

		for i := len(raw) - 2; i > 0; i-- {

			if raw[i-1] == '\'' || isDigit(rune(raw[i-1])) {
				bitstring += string(raw[i-1])
				continue
			}
			break
		}

		bitstring += `B`

		_l = _l - len(bitstring) - 1
		if delim := raw[_l]; delim != '#' {
			err = errorTxt("Missing '#' delimiter for Name/UID pair; found " + string(delim))
			return
		}

		if nou.UID, err = r.BitString(bitstring); err != nil {
			return
		}
	}

	var dn *DistinguishedName
	if dn, err = r.DistinguishedName(raw[:_l]); err == nil {
		nou.DN = *dn
	}

	return
}

// parseDN returns a distinguishedName or an error.  The
// function respects https://tools.ietf.org/html/rfc4514
func parseDN(str string) (*DistinguishedName, error) {
	var dn = &DistinguishedName{RDNs: make([]*RelativeDistinguishedName, 0)}
	if trimS(str) == "" {
		return dn, nil
	}

	var (
		rdn                   = &RelativeDistinguishedName{}
		attr                  = &AttributeTypeAndValue{}
		escaping              bool
		startPos              int
		appendAttributesToRDN = func(end bool) {
			rdn.Attributes = append(rdn.Attributes, attr)
			attr = &AttributeTypeAndValue{}
			if end {
				dn.RDNs = append(dn.RDNs, rdn)
				rdn = &RelativeDistinguishedName{}
			}
		}
	)

	// Loop through each character in the string and
	// build up the attribute type and value pairs.
	// We only check for ascii characters here, which
	// allows us to iterate over the string byte by byte.
	for i := 0; i < len(str); i++ {
		char := str[i]
		switch {
		case escaping:
			escaping = false
		case char == '\\':
			escaping = true
		case char == '=' && len(attr.Type) == 0:
			if err := attr.setType(str[startPos:i]); err != nil {
				return nil, err
			}
			startPos = i + 1
		case isDNDelim(char):
			if len(attr.Type) == 0 {
				return dn, errorTxt("incomplete type, value pair")
			}
			if err := attr.setValue(str[startPos:i]); err != nil {
				return nil, err
			}

			startPos = i + 1
			last := char == ',' || char == ';'
			appendAttributesToRDN(last)
		}
	}

	if len(attr.Type) == 0 {
		return dn, errorTxt("DN ended with incomplete type, value pair")
	}

	if err := attr.setValue(str[startPos:]); err != nil {
		return dn, err
	}
	appendAttributesToRDN(true)

	return dn, nil
}

func isDNDelim(char byte) bool {
	return char == ',' || char == '+' || char == ';'
}

/*
Equal returns true if the [DistinguishedName] is equal as defined in
[Section 4.2.15 of RFC4517] (distinguishedNameMatch).

Returns true if they have the same number of relative distinguished names
and corresponding relative distinguished names (by position) are the same.

[Section 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r *DistinguishedName) Equal(other *DistinguishedName) bool {
	if len(r.RDNs) != len(other.RDNs) {
		return false
	}
	for i := range r.RDNs {
		if !r.RDNs[i].Equal(other.RDNs[i]) {
			return false
		}
	}
	return true
}

/*
AncestorOf returns true if the other [DistinguishedName] consists of at
least one RDN followed by all the RDNs of the current [DistinguishedName].

  - "ou=widgets,o=acme.com" is an ancestor of "ou=sprockets,ou=widgets,o=acme.com"
  - "ou=widgets,o=acme.com" is not an ancestor of "ou=sprockets,ou=widgets,o=foo.com"
  - "ou=widgets,o=acme.com" is not an ancestor of "ou=widgets,o=acme.com"
*/
func (r *DistinguishedName) AncestorOf(other *DistinguishedName) bool {
	if len(r.RDNs) >= len(other.RDNs) {
		return false
	}
	// Take the last `len(r.RDNs)` RDNs from the other DistinguishedName to compare against
	otherRDNs := other.RDNs[len(other.RDNs)-len(r.RDNs):]
	for i := range r.RDNs {
		if !r.RDNs[i].Equal(otherRDNs[i]) {
			return false
		}
	}
	return true
}

/*
Equal returns true if the [RelativeDistinguishedName] is equal as defined
in [Section 4.2.15 of RFC4517] (distinguishedNameMatch).

Relative distinguished names are the same if and only if they have the
same number of AttributeTypeAndValues and each attribute of the first RDN
is the same as the attribute of the second RDN with the same attribute type.

The order of attributes is not significant. Case of attribute types is not
significant.

[Section 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r *RelativeDistinguishedName) Equal(other *RelativeDistinguishedName) bool {
	if len(r.Attributes) != len(other.Attributes) {
		return false
	}
	return r.hasAllAttributes(other.Attributes) && other.hasAllAttributes(r.Attributes)
}

func (r *RelativeDistinguishedName) hasAllAttributes(attrs []*AttributeTypeAndValue) bool {
	for _, attr := range attrs {
		found := false
		for _, myattr := range r.Attributes {
			if myattr.Equal(attr) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

/*
Equal returns true if the [AttributeTypeAndValue] is equivalent to the
specified [AttributeTypeAndValue].  Case of the attribute type is not
significant
*/
func (r *AttributeTypeAndValue) Equal(other *AttributeTypeAndValue) bool {
	return eqf(r.Type, other.Type) && r.Value == other.Value
}

/*
EqualFold returns true if the distinguishedNames are equal as defined in
[Section 4.2.15 of RFC4517] (distinguishedNameMatch).

Returns true if they have the same number of relative distinguished names
and corresponding relative distinguished names (by position) are the same.

Case of the attribute type and value is not significant.

[Section 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r *DistinguishedName) EqualFold(other *DistinguishedName) bool {
	if len(r.RDNs) != len(other.RDNs) {
		return false
	}

	for i := range r.RDNs {
		if !r.RDNs[i].EqualFold(other.RDNs[i]) {
			return false
		}
	}
	return true
}

/*
AncestorOfFold returns true if the other DN consists of at least one RDN
followed by all the RDNs of the current DN. Case of the attribute type
and value is not significant
*/
func (r *DistinguishedName) AncestorOfFold(other *DistinguishedName) bool {
	if len(r.RDNs) >= len(other.RDNs) {
		return false
	}

	// Take the last `len(r.RDNs)` RDNs from the other DN to compare against
	otherRDNs := other.RDNs[len(other.RDNs)-len(r.RDNs):]
	for i := range r.RDNs {
		if !r.RDNs[i].EqualFold(otherRDNs[i]) {
			return false
		}
	}
	return true
}

/*
EqualFold returns true if the relativeDistinguishedNames are equal as
defined in [Section 4.2.15 of RFC4517] (distinguishedNameMatch).

Case of the attribute type is not significant.

[Section 4.2.15 of RFC4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.15
*/
func (r *RelativeDistinguishedName) EqualFold(other *RelativeDistinguishedName) bool {
	if len(r.Attributes) != len(other.Attributes) {
		return false
	}
	return r.hasAllAttributesFold(other.Attributes) && other.hasAllAttributesFold(r.Attributes)
}

func (r *RelativeDistinguishedName) hasAllAttributesFold(attrs []*AttributeTypeAndValue) bool {
	for _, attr := range attrs {
		found := false
		for _, myattr := range r.Attributes {
			if myattr.EqualFold(attr) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

/*
EqualFold returns true if the [AttributeTypeAndValue] is equivalent to
the specified [AttributeTypeAndValue].  Case of the attribute type and
value is not significant
*/
func (r *AttributeTypeAndValue) EqualFold(other *AttributeTypeAndValue) bool {
	return eqf(r.Type, other.Type) && eqf(r.Value, other.Value)
}

// foldString returns a folded string such that foldString(x) == foldString(y)
// is identical to bytes.EqualFold(x, y).
// based on https://go.dev/src/encoding/json/fold.go
func foldString(s string) string {
	builder := newStrBuilder()
	for _, char := range s {
		// Handle single-byte ASCII.
		if char < runeSelf {
			if 'A' <= char && char <= 'Z' {
				char += 'a' - 'A'
			}
			builder.WriteRune(char)
			continue
		}

		builder.WriteRune(foldRune(char))
	}
	return builder.String()
}

// foldRune is returns the smallest rune for all runes in the same fold set.
func foldRune(r rune) rune {
	for {
		r2 := sfold(r)
		if r2 <= r {
			return r
		}
		r = r2
	}
}
