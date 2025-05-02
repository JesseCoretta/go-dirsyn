package dirsyn

/*
url.go contains RFC4516 LDAP URL types and methods with minor
extensions for ACIv3 use.
*/

/*
URL implements [§ 2 of RFC4516]:

	ldapurl     = scheme COLON SLASH SLASH [host [COLON port]]
	                 [SLASH dn [QUESTION [attributes]
	                 [QUESTION [scope] [QUESTION [filter]
	                 [QUESTION extensions]]]]]
	                                ; <host> and <port> are defined
	                                ;   in Sections 3.2.2 and 3.2.3
	                                ;   of [RFC3986].
	                                ; <filter> is from Section 3 of
	                                ;   [RFC4515], subject to the
	                                ;   provisions of the
	                                ;   "Percent-Encoding" section
	                                ;   below.
	scheme      = "ldap"
	dn          = distinguishedName ; From Section 3 of [RFC4514],
	                                ; subject to the provisions of
	                                ; the "Percent-Encoding"
	                                ; section below.
	attributes  = attrdesc *(COMMA attrdesc)
	attrdesc    = selector *(COMMA selector)
	selector    = attributeSelector ; From Section 4.5.1 of
	                                ; [RFC4511], subject to the
	                                ; provisions of the
	                                ; "Percent-Encoding" section
	                                ; below.
	scope       = "base" / "one" / "sub"
	extensions  = extension *(COMMA extension)
	extension   = [EXCLAMATION] extype [EQUALS exvalue]
	extype      = oid               ; From section 1.4 of [RFC4512].
	exvalue     = LDAPString        ; From section 4.1.2 of
	                                ; [RFC4511], subject to the
	                                ; provisions of the
	                                ; "Percent-Encoding" section
	                                ; below.
	EXCLAMATION = %x21              ; exclamation mark ("!")
	SLASH       = %x2F              ; forward slash ("/")
	COLON       = %x3A              ; colon (":")
	QUESTION    = %x3F              ; question mark ("?")

# Notice of non-standard extensions

While the official ABNF above only specifies "ldap" as a valid scheme, this
implementation has been expanded to allow "ldaps://" and "ldapi:///" as well.

Additionally, in addition to the use of an attribute selector, an instance of
[ACIAttributeBindTypeOrValue] may be used. These choices are mutually exclusive.
Note that use of an [ACIAttributeBindTypeOrValue] is only meaningful if the
URL is used in the construction of a Netscape ACIv3 [Instruction] instance.

[§ 2 of RFC4516]: https://datatracker.ietf.org/doc/html/rfc4516#section-2
*/
type URL struct {
	Scheme     string                        // "ldap", "ldaps", "ldapi"; case is not significant
	Host       string                        // host
	Port       string                        // service port
	DN         DistinguishedName             // distinguished name
	Attributes []string                      // comma-separated attribute selector; mutex of ATBTV
	ATBTV      ACIv3AttributeBindTypeOrValue // attributeBindTypeOrValue; mutex of attributes
	Scope      string                        // RFC4511 Search Scope: "base", "one", or "sub"; case is not significant
	Filter     Filter                        // RFC4515 Search Filter
	Extensions []string                      // LDAP extensions
}

/*
URL returns an instance of [URL] alongside an error following an attempt to parse input.
*/
func (r RFC4516) URL(input string) (URL, error) {
	return marshalURL(input)
}

func marshalURL(input string) (r URL, err error) {

	// Determine kind of scheme and its text length.
	pfxlen, pfxtype := selectURLPrefix(input)
	if pfxlen == -1 {
		err = errorTxt("invalid scheme: URL must begin with ldap://, ldaps:// or ldapi:///")
		return
	}

	// Remove the scheme prefix.
	remainder := input[pfxlen:]
	r = URL{Scheme: pfxtype}

	// If the URL is simply "scheme:///", this is fine.
	if input[len(input)-3:] == "///" {
		return
	}

	var rest string
	if rest, err = r.setHostPort(remainder, pfxtype); err != nil {
		return
	}

	parts := split(rest, "?")

	// Throw an error if any trailing content is found
	if len(parts) > 5 {
		err = errorTxt("error reading LDAP URL: unsupported trailing content found: " +
			join(parts[5:], ` `))
		return
	}

	for _, err = range []error{
		r.setDN(parts),
		r.setAttributesOrATBTV(parts),
		r.setScope(parts),
		r.setFilter(parts),
		r.setExtensions(parts),
	} {
		if err != nil {
			break
		}
	}

	return
}

func (r *URL) setHostPort(input, pfxtype string) (rest string, err error) {
	// The first part up to the first "/" is considered the host[:port] section.
	var hostPort string
	slashIdx := stridx(input, "/")
	if slashIdx != -1 {
		hostPort = input[:slashIdx]
		rest = input[slashIdx+1:]
	} else {
		// No slash means the entire string is just the host (without DN).
		hostPort = input
		rest = ""
	}

	// Process host and optional port.
	if hostPort != "" {
		colonIdx := stridx(hostPort, ":")
		if colonIdx != -1 {
			r.Host = hostPort[:colonIdx]
			// Validate that the port is numeric.
			var n int
			if n, err = atoi(hostPort[colonIdx+1:]); err != nil {
				err = errorTxt("invalid port: service port must be numeric")
				return
			} else if !(1 <= n && n <= 65535) {
				err = errorTxt("invalid port: service port number must be unsigned and no greater than 65535")
				return
			}
			r.Port = hostPort[colonIdx+1:]
		} else {
			r.Host = hostPort
		}
	}

	return
}

func (r *URL) setDN(parts []string) (err error) {
	// The rest of the URI (after the host[:port] part) is the DN
	// and, optionally, the query components separated by '?':
	//
	//   dn ? attributes ? scope ? filter ? extensions
	if len(parts) > 0 && len(parts[0]) > 0 {
		var dec string
		if dec, err = percentDecode(parts[0]); err != nil {
			err = errorTxt("error decoding DN '" + parts[0] + "': " + err.Error())
		} else if r.DN, err = marshalDistinguishedName(dec); err != nil {
			err = errorTxt("error parsing DN '" + dec + "': " + err.Error())
		}
	}

	return
}

func (r *URL) setAttributesOrATBTV(parts []string) (err error) {
	// Process attributes if present.
	if len(parts) > 1 && parts[1] != "" {
		if cntns(parts[1], `#`) {
			// If an octothorpe (#) is present, this undoubtedly
			// means that an AttributeBindTypeOrValue is in use.
			var a ACIv3AttributeBindTypeOrValue
			if a, err = marshalACIv3AttributeBindTypeOrValue(parts[1]); err == nil {
				r.ATBTV = a
			}
		} else {
			rawAttrs := splitAndTrim(parts[1], ",")
			for _, attr := range rawAttrs {
				var dec string
				if dec, err = percentDecode(attr); err != nil {
					err = errorTxt("error decoding attribute \": " + attr + "\": " + err.Error())
					break
				}

				r.Attributes = append(r.Attributes, dec)
			}
		}
	}

	return
}

func (r *URL) setScope(parts []string) (err error) {
	// Process scope if present.
	if len(parts) > 2 && parts[2] != "" {
		r.Scope = lc(parts[2])
		// Validate that the scope is one of the allowed values.
		switch r.Scope {
		case "base", "one", "sub":
			// valid
		default:
			err = errorTxt("invalid scope: must be one of 'base', 'one', or 'sub'")
		}
	}

	return
}

func (r *URL) setFilter(parts []string) (err error) {

	// Process filter if present.
	if len(parts) > 3 && parts[3] != "" {
		var dec string
		if dec, err = percentDecode(parts[3]); err != nil {
			err = errorTxt("error decoding filter: " + err.Error())
		} else if r.Filter, err = marshalFilter(dec); err != nil {
			err = errorTxt("error parsing filter: " + err.Error())
		}
	} else {
		r.Filter = invalidFilter{} // prevent Stringer panics
	}

	return
}

func (r *URL) setExtensions(parts []string) (err error) {
	// Process extensions if present.
	if len(parts) > 4 && parts[4] != "" {
		rawExts := splitAndTrim(parts[4], ",")
		for _, ext := range rawExts {
			var dec string
			if dec, err = percentDecode(ext); err != nil {
				err = errorTxt("error decoding extension \": " + ext + "\": " + err.Error())
				break
			}

			r.Extensions = append(r.Extensions, dec)
		}
	}

	return
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *URL) IsZero() bool { return r == nil }

/*
String returns the string representation of the receiver instance.
*/
func (r URL) String() string {
	chopTrailingDelim := func(str string) string {
		return trimR(trimR(str, "/"), "?")
	}

	var s string
	switch r.Scheme {
	case "ldap", "ldaps":
		s += r.Scheme + "://"
		if r.Host != "" {
			s += r.Host
			if r.Port != "" {
				s += ":" + r.Port
			}
		}
	case "ldapi":
		s += "ldapi://"
	default:
		return s
	}

	s += "/"

	if dn := r.DN.String(); dn != "" {
		s += dn // implicit localhost
	}

	// If there is NOTHING beyond the DN, we can stop here.
	if !(len(r.Attributes) > 0 ||
		!r.ATBTV.IsZero() ||
		len(r.Scope) > 0 ||
		r.Filter != nil ||
		len(r.Extensions) > 0) {
		return chopTrailingDelim(s) + "///"
	}

	s += "?"

	if len(r.Attributes) > 0 {
		s += join(r.Attributes, ",")
	} else if !r.ATBTV.IsZero() {
		s += r.ATBTV.String()
	}

	s += "?" + r.Scope + "?"

	if !r.Filter.IsZero() {
		s += r.Filter.String()
	}

	// Only use another "?" delimiter IF any
	// extensions were specified.
	if len(r.Extensions) > 0 {
		s += "?" + join(r.Extensions, ",")
	}

	return chopTrailingDelim(s)
}

func selectURLPrefix(input string) (l int, typ string) {
	l = -1

	var prefixes map[string]string = map[string]string{
		`ldap`:  "ldap://",
		`ldaps`: "ldaps://",
		`ldapi`: "ldapi:///",
	}

	for k, v := range prefixes {
		if hasPfx(lc(input), v) {
			l = len(v)
			typ = k
			break
		}
	}

	return
}
