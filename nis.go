package dirsyn

/*
NetgroupTriple implements the NIS Netgroup Triple type.  Instances of
this type are produced following a successful execution of the
[RFC2307.NetgroupTriple] function.

A zero instance of this type is equal to:

	("-","-","-")

From [§ 2.4 of RFC 2307]:

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

From [§ 1.4 of RFC 4512]:

	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A     ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT         ; "0"-"9"
	LDIGIT  = %x31-39               ; "1"-"9"
	HYPHEN  = %x2D                  ; hyphen ("-")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 2.4 of RFC 2307]: https://datatracker.ietf.org/doc/html/rfc2307#section-2.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type NetgroupTriple struct {
	Hostname IA5String `asn1:"tag:0,optional"`
	Username IA5String `asn1:"tag:1,optional"`
	Domain   IA5String `asn1:"tag:2,optional"`
}

/*
String returns the string representation of the receiver instance.
*/
func (r NetgroupTriple) String() string {
	var trips []string
	for _, ia5 := range []IA5String{
		r.Hostname,
		r.Username,
		r.Domain,
	} {
		if ia5.IsZero() {
			// Yes, a zero string is also acceptable,
			// but a hyphen Just Looks Better™.
			trips = append(trips, `-`)
		} else {
			trips = append(trips, ia5.String())
		}
	}

	return `(` + join(trips, `,`) + `)`
}

/*
NISNetgroupTriple returns an instance of [NetgroupTriple] alongside an error.

The input value type must be a string, such as `("laptop","jesse","example.com")`
or `("-","-","-")`.
*/
func (r RFC2307) NetgroupTriple(x any) (trip NetgroupTriple, err error) {
	var raw string
	if raw, err = assertString(x, 4, "NIS Netgroup Triple"); err != nil {
		return
	}

	if err = validTripleEncap(raw); err != nil {
		return
	}

	value := raw[1 : len(raw)-1]
	ngt := splitUnescaped(value, `,`, `\`)

	if len(ngt) != 3 {
		err = errorTxt("NIS Netgroup Triple does not contain exactly three (3) keystring/hyphen/null values")
		return
	}

	var id RFC4517

	var _trip NetgroupTriple

	for i := 0; i < len(ngt) && err == nil; i++ {
		var ia5 IA5String
		ia5, err = id.IA5String(ngt[i])
		_trip.setNetgroupTripleFieldByIndex(i, ia5)
	}

	if err == nil {
		trip = _trip
	}

	return
}

func validTripleEncap(raw string) (err error) {
	if !(raw[0] == '(' && raw[len(raw)-1] == ')') {
		err = errorTxt("NIS Netgroup Triple encapsulation error")
	}

	return
}

func (r *NetgroupTriple) setNetgroupTripleFieldByIndex(idx int, val any) {
	var ia5 IA5String

	switch tv := val.(type) {
	case string:
		if tv == "" {
			tv = "-"
		}
		ia5 = IA5String(tv)
	case IA5String:
		ia5 = tv
	default:
		return
	}

	switch idx {
	case 0:
		r.Hostname = ia5
	case 1:
		r.Username = ia5
	case 2:
		r.Domain = ia5
	}

	return
}

/*
BootParameter implements the NIS BootParameter type.  Instances of this type
are produced following a successful execution of the [RFC2307.BootParameter]
function.

From [§ 2.4 of RFC 2307]:

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

From [§ 1.4 of RFC 4512]:

	keystring = leadkeychar *keychar
	leadkeychar = ALPHA
	keychar = ALPHA / DIGIT / HYPHEN

	ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT       ; "0"-"9"
	LDIGIT  = %x31-39             ; "1"-"9"
	HYPHEN  = %x2D ; hyphen ("-")

From [§ 3.2 of RFC 4517]:

	IA5String          = *(%x00-7F)

[§ 2.4 of RFC 2307]: https://datatracker.ietf.org/doc/html/rfc2307#section-2.4
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
*/
type BootParameter [3]string

/*
String returns the string representation of the receiver instance.
*/
func (r BootParameter) String() (bp string) {
	var boots []string
	for _, keystr := range r {
		if len(keystr) > 0 {
			boots = append(boots, keystr)
		}
	}

	if len(boots) == 3 {
		bp = boots[0] + `=` + boots[1] + `:` + boots[2]
	}

	return
}

/*
BootParameter returns an error following an analysis of x in the context
of a NIS Boot Parameter.
*/
func (r RFC2307) BootParameter(x any) (bp BootParameter, err error) {
	var raw string

	switch tv := x.(type) {
	case string:
		if len(tv) < 5 {
			err = errorBadLength("Boot Parameter", 0)
			return
		}
		raw = tv
	default:
		err = errorBadType("Boot Parameter")
		return
	}

	idx := idxr(raw, '=')
	if idx == -1 {
		err = errorTxt("Missing '=' delimiter for NIS Boot Parameter")
		return
	}

	idx2 := idxr(raw, ':')
	if idx2 == -1 {
		err = errorTxt("Missing ':' delimiter for NIS Boot Parameter")
		return
	}

	var bps BootParameter
	var id RFC4517

	for iidx, slice := range []string{
		raw[:idx],         // key
		raw[idx+1 : idx2], // server
		raw[idx2+1:],      // path
	} {
		if _, err = id.IA5String(slice); err != nil {
			break
		}
		bps[iidx] = slice
	}

	if err == nil {
		bp = bps
	}

	return
}
