package dirsyn

import (
	"fmt"
	"strings"
)

/*
NISNetgroupTriple returns an error following an analysis of x in the
context of a NIS Netgroup Triple.

From § 2.4 of RFC 2307:

	nisnetgrouptriple = "(" hostname "," username "," domainname ")"
	hostname          = "" / "-" / keystring
	username          = "" / "-" / keystring
	domainname        = "" / "-" / keystring

ASN.1 definition:

	nisNetgroupTripleSyntax ::= SEQUENCE {
		hostname   [0] IA5String OPTIONAL,
		username   [1] IA5String OPTIONAL,
		domainname [2] IA5String OPTIONAL
	}

From § 1.4 of RFC 4512:

	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A   	; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT       	; "0"-"9"
	LDIGIT  = %x31-39               ; "1"-"9"
	HYPHEN  = %x2D                  ; hyphen ("-")
*/
func NISNetgroupTriple(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) < 4 {
			err = fmt.Errorf("Insufficient length '%d' for NIS Netgroup Triple", len(tv))
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for NIS Netgroup Triple", tv)
		return
	}

	if !(raw[0] == '(' && raw[len(raw)-1] == ')') {
		err = fmt.Errorf("NIS Netgroup Triple encapsulation error")
		return
	}

	value := raw[1 : len(raw)-1]

	ngt := splitUnescaped(value, `,`, `\`)
	for _, slice := range ngt {
		if len(slice) == 0 || slice == `-` {
			continue
		} else if !isKeystring(slice) {
			fmt.Errorf("NIS Netgroup Triple element '%s'", slice)
			break
		}
	}

	return
}

/*
BootParameter returns an error following an analysis of x in the context
of a NIS Boot Parameter.

	bootparameter     = key "=" server ":" path
	key               = keystring
	server            = keystring
	path              = keystring

ASN.1 definition:

	bootParameterSyntax ::= SEQUENCE {
	 key     IA5String,
	 server  IA5String,
	 path    IA5String
	}
*/
func BootParameter(x any) (err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) < 5 {
			err = fmt.Errorf("Insufficient length '%d' for Boot Parameter", len(tv))
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Boot Parameter", tv)
		return
	}

	idx := strings.IndexRune(raw, '=')
	if idx == -1 {
		err = fmt.Errorf("Missing '=' delimiter for NIS Boot Parameter")
		return
	}

	idx2 := strings.IndexRune(raw[idx+1:], ':')
	if idx2 == -1 {
		err = fmt.Errorf("Missing ':' delimiter for NIS Boot Parameter")
		return
	}

	for _, slice := range []string{
		raw[:idx],         // key
		raw[idx+1 : idx2], // server
		raw[idx2+1:],      // path
	} {
		if err := IA5String(slice); err != nil {
			break
		}
	}

	return
}
