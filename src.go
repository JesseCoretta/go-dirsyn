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

/*
Sources extends a method for each constructor type.

This is merely a portable alternative to manual allocation of
individual constructor type variables, e.g.:

	  var (
		r X690
		s RFC4517
		n NetscapeACIv3
	  )

	  der, err := r.DER(args)
	  ...
	  tim, err := s.GeneralizedTime(args)
	  ...
	  aci, err := n.ACIv3Instruction(args)

... thus, instead, allowing:

	var r Sources
	der, err := r.X690().DER(args)
	...
	tim, err := r.RFC4517().GeneralizedTime(args)
	...
	aci, err := r.ACIv3().ACIv3Instruction(args)
	...

Instances of this type are most useful when several types are being managed
together, particularly in one location or process.
*/
type Sources struct{}

/*
ACIv3 returns the [NetscapeACIv3] constructor type.
*/
func (r Sources) ACIv3() NetscapeACIv3 { return NetscapeACIv3{} }

/*
X501 returns the ITU-T Rec. [X501] constructor type.
*/
func (r Sources) X501() X501 { return X501{} }

/*
X520 returns the ITU-T Rec. [X520] constructor type.
*/
func (r Sources) X520() X520 { return X520{} }

/*
X680 returns the ITU-T Rec. [X680] constructor type.
*/
func (r Sources) X680() X680 { return X680{} }

/*
X690 returns the ITU-T Rec. [X690] constructor type.
*/
func (r Sources) X690() X690 { return X690{} }

/*
RFC2307 returns the [RFC2307] constructor type.
*/
func (r Sources) RFC2307() RFC2307 { return RFC2307{} }

/*
RFC3672 returns the [RFC3672] constructor type.
*/
func (r Sources) RFC3672() RFC3672 { return RFC3672{} }

/*
RFC4511 returns the [RFC4511] constructor type.
*/
func (r Sources) RFC4511() RFC4511 { return RFC4511{} }

/*
RFC4512 returns the [RFC4512] constructor type.
*/
func (r Sources) RFC4512() RFC4512 { return RFC4512{} }

/*
RFC4514 returns the [RFC4514] constructor type.
*/
func (r Sources) RFC4514() RFC4514 { return RFC4514{} }

/*
RFC4515 returns the [RFC4515] constructor type.
*/
func (r Sources) RFC4515() RFC4515 { return RFC4515{} }

/*
RFC4516 returns the [RFC4516] constructor type.
*/
func (r Sources) RFC4516() RFC4516 { return RFC4516{} }

/*
RFC4517 returns the [RFC4517] constructor type.
*/
func (r Sources) RFC4517() RFC4517 { return RFC4517{} }

/*
RFC4523 returns the [RFC4523] constructor type.
*/
func (r Sources) RFC4523() RFC4523 { return RFC4523{} }

/*
RFC4530 returns the [RFC4530] constructor type.
*/
func (r Sources) RFC4530() RFC4530 { return RFC4530{} }

type (
	NetscapeACIv3 struct{ *SubschemaSubentry }

	X501 struct{ *standard } // ITU-T Rec. X.501
	X520 struct{ *standard } // ITU-T Rec. X.520
	X680 struct{ *standard } // ITU-T Rec. X.680
	X690 struct{ *standard } // ITU-T Rec. X.690

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
Document returns the string representation of the [ITU-T Rec. X.690] document URL.

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
func (r X690) Document() string { return itutURLPrefix + `X.690` }

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
