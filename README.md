[![RFC4514](https://img.shields.io/badge/RFC-4514-blue)](https://datatracker.ietf.org/doc/html/rfc4514) [![RFC4517](https://img.shields.io/badge/RFC-4517-blue)](https://datatracker.ietf.org/doc/html/rfc4517) [![RFC4530](https://img.shields.io/badge/RFC-4530-blue)](https://datatracker.ietf.org/doc/html/rfc4530) [![RFC2307](https://img.shields.io/badge/RFC-2307-blue)](https://datatracker.ietf.org/doc/html/rfc2307) [![RFC3672](https://img.shields.io/badge/RFC-3672-blue)](https://datatracker.ietf.org/doc/html/rfc3672) [![Reference](https://pkg.go.dev/badge/github.com/JesseCoretta/go-dirsyn.svg)](https://pkg.go.dev/github.com/JesseCoretta/go-dirsyn) [![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-dirsyn/blob/main/LICENSE) [![Issues](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-dirsyn/issues) [![Experimental](https://img.shields.io/badge/experimental-blue?logoColor=blue&label=%F0%9F%A7%AA%20%F0%9F%94%AC&labelColor=blue&color=gray)](https://github.com/JesseCoretta/JesseCoretta/blob/main/EXPERIMENTAL.md) [![Volatility Warning](https://img.shields.io/badge/volatile-darkred?label=%F0%9F%92%A5&labelColor=white&color=orange&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/VOLATILE.md) [![Help Animals](https://img.shields.io/badge/help_animals-gray?label=%F0%9F%90%BE%20%F0%9F%98%BC%20%F0%9F%90%B6&labelColor=yellow)](https://github.com/JesseCoretta/JesseCoretta/blob/main/DONATIONS.md)

![dirsyn_logo_small](https://github.com/user-attachments/assets/cecb115d-1d1b-45cd-b4f6-81b5e34c1e8f)


Package dirsyn implements myriad X.500/LDAP syntax checking functions.

This package was mainly developed for the XDAPL Project, but may be freely
used by anyone needing value syntax verification capabilities related to
directory technologies.

## Status

The current state of this package is EXPERIMENTAL. It should not be used
in mission-critical or production environments, and is prone to breaking
changes at any time.  There are some interesting long-term plans for this
package, so it should continue to evolve and grow over time.

Contributions are most welcome.

## License

The `go-dirsyn` package is released under the terms of the MIT license.
See the repository root for applicable license files.

Content developed or appropriated from external sources, such as that
found within the `dn.go` file, will also contain the relevant license
text within the file comment header.

## Supported Syntaxes

The following syntaxes are supported by this package:

  - Bit String ([RFC 4517 § 3.3.2](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2))
  - Boolean ([RFC 4517 § 3.3.3](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3))
  - Boot Parameter ([RFC 2307 § 2.4](https://datatracker.ietf.org/doc/html/rfc2307#section-2.4))
  - Country String ([RFC 4517 § 3.3.4](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4))
  - Delivery Method ([RFC 4517 § 3.3.5](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.5))
  - Directory String ([RFC 4517 § 3.3.6](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.6))
  - DN ([RFC 4517 § 3.3.9](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.9))
  - Enhanced Guide ([RFC 4517 § 3.3.10](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10))
  - Facsimile Telephone Number ([RFC 4517 § 3.3.11](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11))
  - Fax ([RFC 4517 § 3.3.12](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.12))
  - Generalized Time ([RFC 4517 § 3.3.13](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13))
  - Guide ([RFC 4517 § 3.3.14](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.14))
  - IA5 String ([RFC 4517 § 3.3.15](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.15))
  - Integer ([RFC 4517 § 3.3.16](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.16))
  - JPEG ([RFC 4517 § 3.3.17](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.17))
  - NIS Netgroup Triple ([RFC 2307 § 2.4](https://datatracker.ietf.org/doc/html/rfc2307#section-2.4))
  - Name and Optional UID ([RFC 4517 § 3.3.21](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21))
  - Numeric String ([RFC 4517 § 3.3.23](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23))
  - Octet String ([RFC 4517 § 3.3.25](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.25))
  - OID ([RFC 4517 § 3.3.26](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.26))
  - Other Mailbox ([RFC 4517 § 3.3.27](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.27))
  - Postal Address ([RFC 4517 § 3.3.28](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.28))
  - Printable String ([RFC 4517 § 3.3.29](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29))
  - Substring Assertion ([RFC 4517 § 3.3.30](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30))
  - Subtree Specification ([Appendix A, RFC 3672](https://datatracker.ietf.org/doc/html/rfc3672#appendix-A))
  - Telephone Number ([RFC 4517 § 3.3.31](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.31))
  - Teletex Terminal Identifier ([RFC 4517 § 3.3.32](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.32))
  - Telex Number ([RFC 4517 § 3.3.33](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.33))
  - UTC Time ([RFC 4517 § 3.3.34](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.34))
  - UUID ([RFC 4530 § 2.1](https://datatracker.ietf.org/doc/html/rfc4530#section-2.1))

The following [RFC 4517](https://datatracker.ietf.org/doc/html/rfc4517) syntaxes are not supported by this package:

  - Attribute Type Description 
  - DIT Content Rule Description 
  - DIT Structure Rule Description 
  - LDAP Syntax Description 
  - Matching Rule Description 
  - Matching Rule Use Description 
  - Name Form Description 
  - Object Class Description 

For parsing of the above eight (8) syntaxes, see [`go-antlr4512`](https://github.com/JesseCoretta/go-antlr4512), or the full-featured [`go-schemax`](https://github.com/JesseCoretta/go-schemax).

Additionally, to parse Netscape's "aci" syntax, see [`go-antlraci`](https://github.com/JesseCoretta/go-antlraci), or the full-featured [`go-aci`](https://github.com/Jessecoretta/go-aci).

## ASN.1 considerations

While this package offers complete syntax parsing capabilities, support for ASN.1 encoding and decoding of package-defined type instances is limited. Not all types are eligible for ASN.1 support at this time. One example of this is the [Subtree Specification](https://datatracker.ietf.org/doc/html/rfc3672#appendix-A) type.

Due to its nested nature and its (necessary) use of pointer-based struct field values, limitations of the Go ASN.1 package preclude seamless encoding *AND* decoding of such instances. This may or may not be resolved in future revisions of this package.

