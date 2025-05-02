package dirsyn

/*
standard serves as the basis for all ITU-T recommendations and RFCs
relevant to this package.

Instances of this type are not necessary to use directly.
*/
type standard struct {
	Schema     *SubschemaSubentry
	Parameters map[string][]string
}

type (
	NetscapeACIv3 struct{ *SubschemaSubentry }

	X501 struct{ *standard } // ITU-T Rec. X.501
	X520 struct{ *standard } // ITU-T Rec. X.520
	X680 struct{ *standard } // ITU-T Rec. X.680

	RFC2307 struct{ *standard } // RFC 2307
	RFC3672 struct{ *standard } // RFC 3672
	RFC4511 struct{ *standard } // RFC 4511
	RFC4512 struct{ *standard } // RFC 4512
	RFC4514 struct{ *standard } // RFC 4514
	RFC4515 struct{ *standard } // RFC 4515
	RFC4516 struct{ *standard } // RFC 4516
	RFC4517 struct{ *standard } // RFC 4517
	RFC4523 struct{ *standard } // RFC 4523
	RFC4530 struct{ *standard } // RFC 4530
)

const (
	itutURLPrefix = `https://www.itu.int/rec/T-REC-`
	rfcURLPrefix  = `https://datatracker.ietf.org/doc/html/`
)

/*
Document returns the string representation of the [ITU-T Rec. X.501] document URL.

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func (r X501) Document() string { return itutURLPrefix + `X.501` }

/*
Document returns the string representation of the [ITU-T Rec. X.680] document URL.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
func (r X680) Document() string { return itutURLPrefix + `X.680` }

/*
Document returns the string representation of the [ITU-T Rec. X.520] document URL.

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
func (r X520) Document() string { return itutURLPrefix + `X.520` }

/*
Document returns the string representation of the RFC 2307 document URL.
*/
func (r RFC2307) Document() string { return rfcURLPrefix + `rfc2307` }

/*
Document returns the string representation of the RFC 3672 document URL.
*/
func (r RFC3672) Document() string { return rfcURLPrefix + `rfc3672` }

/*
Document returns the string representation of the RFC 4511 document URL.
*/
func (r RFC4511) Document() string { return rfcURLPrefix + `rfc4511` }

/*
Document returns the string representation of the RFC 4512 document URL.
*/
func (r RFC4512) Document() string { return rfcURLPrefix + `rfc4512` }

/*
Document returns the string representation of the RFC 4514 document URL.
*/
func (r RFC4514) Document() string { return rfcURLPrefix + `rfc4514` }

/*
Document returns the string representation of the RFC 4515 document URL.
*/
func (r RFC4515) Document() string { return rfcURLPrefix + `rfc4515` }

/*
Document returns the string representation of the RFC 4516 document URL.
*/
func (r RFC4516) Document() string { return rfcURLPrefix + `rfc4516` }

/*
Document returns the string representation of the RFC 4517 document URL.
*/
func (r RFC4517) Document() string { return rfcURLPrefix + `rfc4517` }

/*
Document returns the string representation of the RFC 4523 document URL.
*/
func (r RFC4523) Document() string { return rfcURLPrefix + `rfc4523` }

/*
Document returns the string representation of the RFC 4530 document URL.
*/
func (r RFC4530) Document() string { return rfcURLPrefix + `rfc4530` }
