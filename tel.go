package dirsyn

import (
	"fmt"
	"strings"
	"unicode"
)

var ttxRange *unicode.RangeTable

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
*/
func FacsimileTelephoneNumber(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Facsimile Telephone Number")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Facsimile Telephone Number", tv)
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)

	if len(raws) == 0 {
		err = fmt.Errorf("Invalid Facsimile Telephone Number value")
		return
	} else if err = PrintableString(raws[0]); err != nil || len(raws) == 1 {
		return
	}

	raws = raws[1:]
	prms := map[string]uint8{
		`twoDimensional`:  uint8(1),
		`fineResolution`:  uint8(2),
		`unlimitedLength`: uint8(4),
		`b4Length`:        uint8(8),
		`a3Width`:         uint8(16),
		`b4Width`:         uint8(32),
		`uncompressed`:    uint8(64),
	}

	var ct uint8
	for _, slice := range raws {
		bit, found := prms[slice]
		if !found {
			err = fmt.Errorf("Unknown Facsimile Telephone Number PRM value '%s'", slice)
			break
		} else if ct&bit > 0 {
			err = fmt.Errorf("Duplicate '%s' Facsimile Telephone Number PRM value", slice)
			break
		}
		ct |= bit
	}

	return
}

/*
TelephoneNumber returns an error following an analysis of x in the context
of a Telephone Number.
*/
func TelephoneNumber(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		l := len(tv)
		if l < 7 {
			err = fmt.Errorf("Invalid length '%d' for Telephone Number", l)
			return
		} else if tv[0] != '+' {
			err = fmt.Errorf("Invalid prefix '%c' for Telephone Number", tv[0])
			return
		}
		raw = tv[1:]
	default:
		err = fmt.Errorf("Incompatible type '%T' for Telephone Number", tv)
		return
	}

	runes := []rune{'\'', '\\', '"', '(', ')', '+', ',', '-', '.', '/', ':', '?'}

	for _, ch := range raw {
		char := rune(ch)
		if !(isAlphaNumeric(char) || runeInSlice(char, runes)) {
			err = fmt.Errorf("Invalid character '%c' for Telephone Number", char)
			break
		}
	}

	return
}

/*
Fax returns an error following an analysis of x in the context of a Fax.
*/
func Fax(x any) (err error) {
	err = IA5String(x)
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
func TelexNumber(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Telex Number")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Telex Number", tv)
		return
	}

	raws := splitUnescaped(raw, `$`, `\`)
	if len(raws) != 3 {
		err = fmt.Errorf("Invalid Telex Number Value")
		return
	}

	for _, slice := range raws {
		if err = PrintableString(slice); err != nil {
			break
		}
	}

	return
}

/*
TeletexTerminalIdentifier returns an error following an analysis of x in
the context of a Teletex Terminal Identifier.

From § 3.3.32 of RFC 4517:

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

From § 3.2 of RFC 4517:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter
	COLON              = %x3A  ; colon (":")

From § 1.4 of RFC 4512:

	DOLLAR  = %x24 ; dollar sign ("$")
*/
func TeletexTerminalIdentifier(x any) (err error) {
	var (
		raw  string
		raws []string
	)

	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Teletex Terminal Identifier value")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Teletex Terminal Identifier", tv)
		return
	}

	_raws := splitUnescaped(raw, `$`, `\`)
	var cfound bool
	for i := 0; i < len(_raws); i++ {
		if idx := strings.IndexRune(_raws[i], ':'); idx != -1 {
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
		err = fmt.Errorf("Missing ':' token in Teletex Terminal Identifier")
		return
	}

	if len(raws) == 0 {
		err = fmt.Errorf("Invalid Teletex Terminal Identifier value")
		return
	} else if err = PrintableString(raws[0]); err != nil || len(raws) == 1 {
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
			err = fmt.Errorf("Unknown Teletex Terminal Identifier TTXPRM value '%s'", slice)
			break
		} else if ct&bit > 0 {
			err = fmt.Errorf("Duplicate '%s' Teletex Terminal Identifier TTXPRM value", slice)
			break
		}
		ct |= bit
	}

	return
}

func teletexSuffixValue(x string) (err error) {
	var last rune
	for _, ch := range x {
		if ch == '$' && last != '\\' {
			err = fmt.Errorf("Unescaped '$' character found in TTID suffix")
			break
		} else if !(unicode.Is(ttxRange, ch) || ch == '\\') {
			err = fmt.Errorf("Incompatible char '%c' for UTF0 (in UTFMB)", ch)
			break
		}
		last = rune(ch)
	}

	return
}

func init() {
	ttxRange = &unicode.RangeTable{R16: []unicode.Range16{
		{0x0000, 0x0023, 1},
		{0x0025, 0x005B, 1},
		{0x005D, 0x00FF, 1},
	}}
}
