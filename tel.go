package dirsyn

import "encoding/asn1"

var ftnPRM map[string]uint

const (
	UBTelephoneNumber   int = 32   // X.520: ub-telephone-number INTEGER ::= 32
	UBTeletexTerminalID int = 1024 // X.520: ub-teletex-terminal-id INTEGER ::= 1024
	UBTeletexPrivateUse int = 128  // X.411: ub-teletex-private-use-length INTEGER ::= 128
)

/*
FacsimileTelephoneNumber implements § 3.3.11 of RFC 4517 and clause 6.7.4 of ITU-T Rec. X.520:

From § 3.3.11 of RFC 4517:

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

	FacsimileTelephoneNumber	::= 	SEQUENCE {
		telephoneNumber 	PrintableString (SIZE(1.. ub-telephone-number)),
		parameters 		G3FacsimileNonBasicParameters  OPTIONAL}

	G3FacsimileNonBasicParameters	::=	BIT STRING {
		two-dimensional		(8),
		fine-resolution		(9),
		unlimited-length	(20),
		b4-length		(21),
		a3-width		(22),
		b4-width		(23),
		uncompressed		(30) }
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
	if bit > 31 {
		return
	}

	index := bit / 8
	pos := bit % 8
	r.G3FacsimileNonBasicParameters.Bytes[index] |= 1 << pos
}

/*
FacsimileTelephoneNumber returns an error following an analysis of x in
the context of a Facsimile Telephone Number.

From § 3.3.11 of RFC 4517:

	fax-number       = telephone-number *( DOLLAR fax-parameter )
	telephone-number = PrintableString
	fax-parameter    = "twoDimensional" /
	                   "fineResolution" /
	                   "unlimitedLength" /
	                   "b4Length" /
	                   "a3Width" /
	                   "b4Width" /
	                   "uncompressed"

From § 1.4 of RFC 4512:

	DOLLAR  = %x24 ; dollar sign ("$")
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
Encode returns the ASN.1 encoding of the receiver instance alongside an error.
*/
func (r FacsimileTelephoneNumber) Encode() (b []byte, err error) {
	b, err = asn1m(r)
	return
}

/*
Decode returns an error following an attempt to decode ASN.1 encoded bytes b into
the receiver instance. This results in the receiver being overwritten with new data.
*/
func (r *FacsimileTelephoneNumber) Decode(b []byte) (err error) {
	var rest []byte
	rest, err = asn1um(b, r)
	if err == nil {
		if len(rest) > 0 {
			err = errorTxt("Extra left-over content found during ASN.1 unmarshal: '" + string(rest) + "'")
		}
	}

	return
}

/*
TelephoneNumber implements § 3.3.31 of RFC 4517 and clause 6.7.1 of ITU-T Rec. X.520:

	PrintableString (SIZE(1..ub-telephone-number))
*/
type TelephoneNumber PrintableString

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
Fax returns an error following an analysis of x in the context of a Fax.
*/
func (r RFC4517) Fax(x any) (err error) {
	_, err = r.IA5String(x)
	return
}

/*
TelexNumber returns an error following an analysis of x in the context
of a Telex Number.

From § 3.3.33 of RFC 4517:

	telex-number  = actual-number DOLLAR country-code DOLLAR answerback
	actual-number = PrintableString
	country-code  = PrintableString
	answerback    = PrintableString

From § 3.2 of RFC 4517:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From § 1.4 of RFC 4512:

	DOLLAR  = %x24 ; dollar sign ("$")
*/
func (r RFC4517) TelexNumber(x any) (err error) {
	var raw string
	if raw, err = assertString(x, 1, "Telex Number"); err != nil {
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)
	if len(raws) != 3 {
		err = errorTxt("Invalid Telex Number value")
		return
	}

	for _, slice := range raws {
		if _, err = r.PrintableString(slice); err != nil {
			break
		}
	}

	return
}

/*
TeletexTerminalIdentifier implements § 3.3.32 of RFC 4517 and

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

ASN.1 definition, per ITU-T Rec. X.520

		TeletexTerminalIdentifier ::= SEQUENCE {
			teletexTerminal PrintableString (SIZE(1..ub-teletex-terminal-id)),
			parameters	TeletexNonBasicParameters OPTIONAL
		}

		ub-teletex-terminal-id INTEGER ::= 1024
	}

From § 3.2 of RFC 4517:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
	COLON              = %x3A  ; colon (":")

From § 1.4 of RFC 4512:

	DOLLAR  = %x24 ; dollar sign ("$")
*/
type TeletexTerminalIdentifier struct {
	TeletexTerminal string                    `asn1:"printable"` // (SIZE(1..ub-teletex-terminal-id)),
	Parameters      TeletexNonBasicParameters `asn1:"set,optional"`
}

/*
TeletexNonBasicParameters is defined in ITU-T Rec. T.62.
*/
type TeletexNonBasicParameters struct {
	GraphicCharacterSets     TeletexString `asn1:"tag:0,optional"` // TeletexString OPTIONAL
	CtrlCharacterSets        TeletexString `asn1:"tag:1,optional"` // TeletexString OPTIONAL
	PageFormats              OctetString   `asn1:"tag:2,optional"` // OCTET STRING OPTIONAL
	MiscTerminalCapabilities TeletexString `asn1:"tag:3,optional"` // TeletexString OPTIONAL
	PrivateUse               TeletexString `asn1:"tag:4,optional"` // OCTET STRING OPTIONAL
}

/*
TeletexTerminalIdentifier returns an error following an analysis of x in
the context of a Teletex Terminal Identifier.
*/
func (r RFC4517) TeletexTerminalIdentifier(x any) (err error) {
	var (
		raw  string
		raws []string
	)

	if raw, err = assertString(x, 1, "Teletex Terminal Identifier"); err != nil {
		return
	}

	_raws := splitUnescaped(raw, `$`, `\`)
	if raws, err = r.processTeletex(_raws); err != nil {
		return
	} else if _, err = r.PrintableString(raws[0]); err != nil || len(raws) == 1 {
		return
	}

	raws = raws[1:]
	ttxs := map[string]uint8{
		`graphic`: uint8(1),
		`control`: uint8(2),
		`misc`:    uint8(4),
		`page`:    uint8(8),
		`private`: uint8(16),
	}

	var ct uint8
	for _, slice := range raws {
		bit, found := ttxs[slice]
		if !found {
			err = errorTxt("Unknown Teletex Terminal Identifier TTXPRM value: " + slice)
			break
		} else if ct&bit > 0 {
			err = errorTxt("Duplicate Teletex Terminal Identifier TTXPRM value: " + slice)
			break
		}
		ct |= bit
	}

	return
}

func (r RFC4517) processTeletex(_raws []string) (raws []string, err error) {
	var cfound bool
	for i := 0; i < len(_raws); i++ {
		if idx := idxr(_raws[i], ':'); idx != -1 {
			cfound = true
			raws = append(raws, _raws[i][:idx])
			if len(raws[i][idx:]) > 1 {
				if err = teletexSuffixValue(raws[i][idx+1:]); err != nil {
					return
				}
			}
		} else {
			raws = append(raws, _raws[i])
		}
	}

	if !cfound {
		err = errorTxt("Teletex Terminal Identifier missing ':' token")
	} else if len(raws) == 0 {
		err = errorTxt("Missing Teletex Terminal Identifier value")
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
