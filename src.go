package dirsyn

type (
	X501 struct{} // ITU-T Rec. X.501
	X520 struct{} // ITU-T Rec. X.520
	X680 struct{} // ITU-T Rec. X.680

	RFC2307 struct{} // RFC 2307
	RFC3672 struct{} // RFC 3672
	RFC4512 struct{} // RFC 4512
	RFC4514 struct{} // RFC 4514
	RFC4515 struct{} // RFC 4515
	RFC4517 struct{} // RFC 4517
	RFC4523 struct{} // RFC 4523
	RFC4530 struct{} // RFC 4530
)

const (
	itutURLPrefix = `https://www.itu.int/rec/T-REC-`
	rfcURLPrefix  = `https://datatracker.ietf.org/doc/html/`
)

/*
URL returns the string representation of the [ITU-T Rec. X.501] document URL.

[ITU-T Rec. X.501]: https://www.itu.int/rec/T-REC-X.501
*/
func (r X501) URL() string { return itutURLPrefix + `X.501` }

/*
URL returns the string representation of the [ITU-T Rec. X.680] document URL.

[ITU-T Rec. X.680]: https://www.itu.int/rec/T-REC-X.680
*/
func (r X680) URL() string { return itutURLPrefix + `X.680` }

/*
URL returns the string representation of the [ITU-T Rec. X.520] document URL.

[ITU-T Rec. X.520]: https://www.itu.int/rec/T-REC-X.520
*/
func (r X520) URL() string { return itutURLPrefix + `X.520` }

/*
URL returns the string representation of the RFC 2307 document URL.
*/
func (r RFC2307) URL() string { return rfcURLPrefix + `rfc2307` }

/*
URL returns the string representation of the RFC 3672 document URL.
*/
func (r RFC3672) URL() string { return rfcURLPrefix + `rfc3672` }

/*
URL returns the string representation of the RFC 4512 document URL.
*/
func (r RFC4512) URL() string { return rfcURLPrefix + `rfc4512` }

/*
URL returns the string representation of the RFC 4514 document URL.
*/
func (r RFC4514) URL() string { return rfcURLPrefix + `rfc4514` }

/*
URL returns the string representation of the RFC 4515 document URL.
*/
func (r RFC4515) URL() string { return rfcURLPrefix + `rfc4515` }

/*
URL returns the string representation of the RFC 4517 document URL.
*/
func (r RFC4517) URL() string { return rfcURLPrefix + `rfc4517` }

/*
URL returns the string representation of the RFC 4523 document URL.
*/
func (r RFC4523) URL() string { return rfcURLPrefix + `rfc4523` }

/*
URL returns the string representation of the RFC 4530 document URL.
*/
func (r RFC4530) URL() string { return rfcURLPrefix + `rfc4530` }