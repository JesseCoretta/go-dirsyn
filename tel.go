package dirsyn

import "encoding/asn1"

var (
	ftnPRM map[string]uint
	ttxs   map[string]uint8
)

const (
	UBTelephoneNumber   int = 32   // X.520: ub-telephone-number INTEGER ::= 32
	UBTeletexTerminalID int = 1024 // X.520: ub-teletex-terminal-id INTEGER ::= 1024
	UBTeletexPrivateUse int = 128  // X.411: ub-teletex-private-use-length INTEGER ::= 128
)

/*
FacsimileTelephoneNumber implements [§ 3.3.11 of RFC 4517] and [ITU-T Rec.
X.520 clause 6.7.4].

From [§ 3.3.11 of RFC 4517]:

	fax-number       = telephone-number *( DOLLAR fax-parameter )
	telephone-number = PrintableString
	fax-parameter    = "twoDimensional" /
	                   "fineResolution" /
	                   "unlimitedLength" /
	                   "b4Length" /
	                   "a3Width" /
	                   "b4Width" /
	                   "uncompressed"

ASN.1 definitions:

	FacsimileTelephoneNumber ::= SEQUENCE {
		telephoneNumber     PrintableString (SIZE(1.. ub-telephone-number)),
		parameters          G3FacsimileNonBasicParameters  OPTIONAL}

	G3FacsimileNonBasicParameters ::= BIT STRING {
		two-dimensional	     (8),
		fine-resolution	     (9),
		unlimited-length     (20),
		b4-length            (21),
		a3-width             (22),
		b4-width             (23),
		uncompressed         (30) }

[§ 3.3.11 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11
[ITU-T Rec. X.520 clause 6.7.4]: https://www.itu.int/rec/T-REC-X.520
*/
type FacsimileTelephoneNumber struct {
	TelephoneNumber               PrintableString `asn1:"printable"`
	G3FacsimileNonBasicParameters asn1.BitString  `asn1:"optional"`
}

func (r FacsimileTelephoneNumber) String() (ftn string) {
	if len(r.TelephoneNumber) == 0 {
		return
	}

	var prms []string
	for name, bit := range ftnPRM {
		if r.isSet(bit) && !strInSlice(name, prms) {
			prms = append(prms, name)
		}
	}

	if len(prms) == 0 {
		ftn = r.TelephoneNumber.String()
		return
	}
	ftn = r.TelephoneNumber.String() + `$` + join(prms, `$`)

	return
}

func (r FacsimileTelephoneNumber) isSet(bit uint) bool {
	if bit > 31 || len(r.G3FacsimileNonBasicParameters.Bytes) == 0 {
		return false
	}

	index := bit / 8
	pos := bit % 8
	return r.G3FacsimileNonBasicParameters.Bytes[index]&(1<<pos) != 0
}

func (r *FacsimileTelephoneNumber) set(bit uint) {
	if bit > 31 || r == nil {
		return
	}

	index := bit / 8
	pos := bit % 8
	r.G3FacsimileNonBasicParameters.Bytes[index] |= 1 << pos
}

/*
FacsimileTelephoneNumber returns an instance of [FacsimileTelephoneNumber]
alongside an error.

From [§ 3.3.11 of RFC 4517]:

	fax-number       = telephone-number *( DOLLAR fax-parameter )
	telephone-number = PrintableString
	fax-parameter    = "twoDimensional" /
	                   "fineResolution" /
	                   "unlimitedLength" /
	                   "b4Length" /
	                   "a3Width" /
	                   "b4Width" /
	                   "uncompressed"

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.11 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11
*/
func (r RFC4517) FacsimileTelephoneNumber(x any) (ftn FacsimileTelephoneNumber, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Facsimile Telephone Number"); err != nil {
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)

	if len(raws) == 0 {
		err = errorTxt("Invalid Facsimile Telephone Number")
		return
	} else if ftn.TelephoneNumber, err = r.PrintableString(raws[0]); err != nil || len(raws) == 1 {
		return
	}

	ftn.G3FacsimileNonBasicParameters = asn1.BitString{
		Bytes:     make([]byte, 4),
		BitLength: 32,
	}

	raws = raws[1:]

	for _, slice := range raws {
		bit, found := ftnPRM[slice]
		if !found {
			err = errorTxt("Unknown Facsimile Telephone Number PRM value: " + slice)
			break
		} else if ftn.isSet(bit) {
			err = errorTxt("Duplicate Facsimile Telephone Number PRM value: " +
				slice + " at bit " + fmtInt(int64(bit), 10))
			break
		}
		ftn.set(bit)
	}

	return
}

/*
TelephoneNumber implements [§ 3.3.31 of RFC 4517] and [ITU-T Rec. X.520 clause 6.7.1]:

	PrintableString (SIZE(1..ub-telephone-number))

[ITU-T Rec. X.520 clause 6.7.1]: https://www.itu.int/rec/T-REC-X.520
[§ 3.3.31 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.31
*/
type TelephoneNumber PrintableString

/*
String returns the string representation of the receiver instance.
*/
func (r TelephoneNumber) String() string {
	return `+` + string(r)
}

/*
TelephoneNumber returns an instance of [TelephoneNumber] alongside an error
following an analysis of x in the context of a Telephone Number.
*/
func (r RFC4517) TelephoneNumber(x any) (tn TelephoneNumber, err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		l := len(tv)
		if !(1 <= l && l <= UBTelephoneNumber) {
			err = errorBadLength("Telephone Number", l)
			return
		} else if tv[0] != '+' {
			err = errorTxt("Telephone Number has invalid prefix: " + string(tv[0]))
			return
		}
		raw = tv[1:]
	default:
		err = errorBadType("Telephone Number")
		return
	}

	runes := []rune{'\'', '\\', '"', '(', ')', '+', ',', '-', '.', '/', ':', '?', ' '}

	// TODO: conform more closely to E.123.
	for _, ch := range raw {
		char := rune(ch)
		if !(isAlphaNumeric(char) || runeInSlice(char, runes)) {
			err = errorBadType("Invalid Telephone Number character: " + string(char))
			return
		}
	}

	if _, err = r.PrintableString(raw); err == nil {
		tn = TelephoneNumber(raw)
	}

	return
}

/*
TelexNumber implements TelexNumber per [§ 3.3.33 of RFC 4517]:

	telex-number  = actual-number DOLLAR country-code DOLLAR answerback
	actual-number = PrintableString
	country-code  = PrintableString
	answerback    = PrintableString

From [§ 3.2 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 3.3.33 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.33
*/
type TelexNumber [3]string

/*
TelexNumber returns an error following an analysis of x in the context
of a Telex Number.
*/
func (r RFC4517) TelexNumber(x any) (tn TelexNumber, err error) {
	var raw string
	if raw, err = assertString(x, 1, "Telex Number"); err != nil {
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)
	if len(raws) != 3 {
		err = errorTxt("Invalid Telex Number value")
		return
	}

	var _tn []string
	var ct int
	for _, slice := range raws {
		if _, err = r.PrintableString(slice); err == nil {
			_tn = append(_tn, slice)
			ct++
		}
	}

	if ct != 3 {
		err = errorTxt("Invalid Telex Number component count; expected 3")
		return
	}

	tn = TelexNumber(_tn)

	return
}

/*
String returns the string representation of the receiver instance.
*/
func (r TelexNumber) String() (str string) {
	if r[0] != "" && r[1] != "" && r[2] != "" {
		str = r[0] + `$` + r[1] + `$` + r[2]
	}

	return
}

/*
TeletexTerminalIdentifier implements [§ 3.3.32 of RFC 4517] and

	teletex-id = ttx-term *(DOLLAR ttx-param)
	ttx-term   = PrintableString          ; terminal identifier
	ttx-param  = ttx-key COLON ttx-value  ; parameter
	ttx-key    = "graphic" / "control" / "misc" / "page" / "private"
	ttx-value  = *ttx-value-octet

	ttx-value-octet = %x00-23
	                  / (%x5C "24")  ; escaped "$"
	                  / %x25-5B
	                  / (%x5C "5C")  ; escaped "\"
	                  / %x5D-FF

ASN.1 definition, per [ITU-T Rec. X.520]:

	TeletexTerminalIdentifier ::= SEQUENCE {
		teletexTerminal PrintableString (SIZE(1..ub-teletex-terminal-id)),
		parameters	TeletexNonBasicParameters OPTIONAL
	}

	ub-teletex-terminal-id INTEGER ::= 1024

From [§ 3.2 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
	COLON              = %x3A  ; colon (":")

From [§ 1.4 of RFC 4512]:

	DOLLAR  = %x24 ; dollar sign ("$")

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.3.32 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.32
*/
type TeletexTerminalIdentifier struct {
	TeletexTerminal string                    `asn1:"printable"` // (SIZE(1..ub-teletex-terminal-id)),
	Parameters      TeletexNonBasicParameters `asn1:"set,optional"`
}

/*
TeletexNonBasicParameters is defined in [ITU-T Rec. X.420].

[ITU-T Rec. X.420]: https://www.itu.int/rec/T-REC-X.420
*/
type TeletexNonBasicParameters struct {
	GraphicCharacterSets     TeletexString `asn1:"tag:0,optional"` // TeletexString OPTIONAL
	CtrlCharacterSets        TeletexString `asn1:"tag:1,optional"` // TeletexString OPTIONAL
	PageFormats              OctetString   `asn1:"tag:2,optional"` // OCTET STRING OPTIONAL
	MiscTerminalCapabilities TeletexString `asn1:"tag:3,optional"` // TeletexString OPTIONAL
	PrivateUse               OctetString   `asn1:"tag:4,optional"` // OCTET STRING OPTIONAL
}

func (r TeletexTerminalIdentifier) String() (s string) {
	s = r.TeletexTerminal
	if r.Parameters.string() != "" {
		s += `$` + r.Parameters.string()
	}
	return
}

func (r TeletexNonBasicParameters) string() string {
	var slice []string
	if len(r.GraphicCharacterSets) > 0 {
		slice = append(slice, string(r.GraphicCharacterSets))
	}
	if len(r.CtrlCharacterSets) > 0 {
		slice = append(slice, string(r.CtrlCharacterSets))
	}
	if len(r.PageFormats) > 0 {
		slice = append(slice, string(r.PageFormats))
	}
	if len(r.MiscTerminalCapabilities) > 0 {
		slice = append(slice, string(r.MiscTerminalCapabilities))
	}
	if len(r.PrivateUse) > 0 {
		slice = append(slice, string(r.PrivateUse))
	}

	var nbp string
	if len(slice) > 0 {
		nbp = join(slice, `$`)
	}

	return nbp
}

/*
TeletexTerminalIdentifier returns an error following an analysis of x in
the context of a Teletex Terminal Identifier.
*/
func (r RFC4517) TeletexTerminalIdentifier(x any) (tti TeletexTerminalIdentifier, err error) {
	var (
		raw string
		raws,
		vals []string
	)

	if raw, err = assertString(x, 1, "Teletex Terminal Identifier"); err != nil {
		return
	}

	_raws := splitUnescaped(raw, `$`, `\`)
	if raws, vals, err = r.processTeletex(_raws[1:]); err != nil {
		return
	} else if _, err = r.PrintableString(_raws[0]); err != nil {
		return
	}

	tti.TeletexTerminal = _raws[0]

	var ct uint8
	for idx, slice := range raws {
		bit, found := ttxs[slice]
		if !found {
			err = errorTxt("Unknown Teletex Terminal Identifier TTXPRM value: " + slice)
			break
		} else if ct&bit > 0 {
			err = errorTxt("Duplicate Teletex Terminal Identifier TTXPRM value: " + slice)
			break
		}
		ct |= bit

		if idx < len(vals) {
			value := vals[idx]

			switch slice {
			case `graphic`:
				tti.Parameters.GraphicCharacterSets = TeletexString(value)
			case `control`:
				tti.Parameters.CtrlCharacterSets = TeletexString(value)
			case `private`:
				tti.Parameters.PrivateUse = OctetString(value)
			case `misc`:
				tti.Parameters.MiscTerminalCapabilities = TeletexString(value)
			case `page`:
				tti.Parameters.PageFormats = OctetString(value)
			}
		}
	}

	return
}

func (r RFC4517) processTeletex(_raws []string) (raws, vals []string, err error) {
	var cfound bool
	for i := 0; i < len(_raws); i++ {
		if idx := idxr(_raws[i], ':'); idx != -1 {
			cfound = true
			raw := _raws[i][:idx]
			aft := _raws[i][idx+1:]
			raws = append(raws, raw)

			if len(aft) > 0 {
				if err = teletexSuffixValue(aft); err != nil {
					return
				}
				vals = append(vals, raw+`:`+aft)
			} else {
				vals = append(vals, raw+`:`)
			}
		} else {
			err = errorTxt("Teletex Terminal Identifier missing ttx-value")
			return
		}
	}

	if !cfound {
		err = errorTxt("Teletex Terminal Identifier missing ':' token")
	} else if len(raws) == 0 {
		err = errorTxt("Missing Teletex Terminal Identifier value")
	} else if len(raws) > UBTeletexTerminalID {
		err = errorTxt("Teletex Terminal Identifier value length out of bounds (>1024)")
	}

	return
}

func teletexSuffixValue(x string) (err error) {
	var last rune
	for _, ch := range x {
		if ch == '$' && last != '\\' {
			err = errorTxt("Unescaped '$' character found in TTID suffix")
			break
		} else if !(ucIs(ttxRange, ch) || ch == '\\') {
			err = errorTxt("Incompatible char for UTF0 (in UTFMB): " + string(ch))
			break
		}
		last = rune(ch)
	}

	return
}

func init() {
	ttxs = map[string]uint8{
		`graphic`: uint8(1),
		`control`: uint8(2),
		`page`:    uint8(4),
		`misc`:    uint8(8),
		`private`: uint8(16),
	}

	ftnPRM = map[string]uint{
		`twoDimensional`:  uint(8),
		`fineResolution`:  uint(9),
		`unlimitedLength`: uint(20),
		`b4Length`:        uint(21),
		`a3Width`:         uint(22),
		`b4Width`:         uint(23),
		`uncompressed`:    uint(30),
	}
}
