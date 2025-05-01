<br>

![dirsyn_logo_small](https://github.com/user-attachments/assets/ae15a556-1478-406f-beac-4d4b52b1d133)

[![Go Report Card](https://goreportcard.com/badge/JesseCoretta/go-dirsyn)](https://goreportcard.com/report/github.com/JesseCoretta/go-dirsyn) [![Reference](https://pkg.go.dev/badge/github.com/JesseCoretta/go-dirsyn.svg)](https://pkg.go.dev/github.com/JesseCoretta/go-dirsyn) [![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-dirsyn/blob/main/LICENSE) [![Issues](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JesseCoretta/go-dirsyn/issues) [![Experimental](https://img.shields.io/badge/experimental-blue?logoColor=blue&label=%F0%9F%A7%AA%20%F0%9F%94%AC&labelColor=blue&color=gray)](https://github.com/JesseCoretta/JesseCoretta/blob/main/EXPERIMENTAL.md) [![Volatility Warning](https://img.shields.io/badge/volatile-darkred?label=%F0%9F%92%A5&labelColor=white&color=orange&cacheSeconds=86400)](https://github.com/JesseCoretta/JesseCoretta/blob/main/VOLATILE.md) [![Help Animals](https://img.shields.io/badge/help_animals-gray?label=%F0%9F%90%BE%20%F0%9F%98%BC%20%F0%9F%90%B6&labelColor=yellow)](https://github.com/JesseCoretta/JesseCoretta/blob/main/DONATIONS.md)

Package dirsyn implements low-level directory syntax parsing and assertion matching rule components.

This package was developed for the XDAPL Project.

## Status

**NOT YET READY FOR GENERAL USE!**

The current state of this package is EXPERIMENTAL and very unstable. It should NOT be used in mission-critical or production environments, and is prone to breaking changes at any time.  There are some interesting long-term plans for this package, so it should continue to evolve and grow.

Much research remains before this package can be relied upon implicitly. Some functionality is present only to serve as a placeholder, and does not exhibit fully standards-compliant behavior at this time.

Contributions are most welcome.

## License

The `go-dirsyn` package is released under the terms of the MIT license. See the repository root for applicable license files.

Content developed or appropriated from external sources, such as that found within the `dn.go` file, will also contain the relevant license text within the file comment header.

## Scope

The scope of this package is intended to, ultimately, cover all of the syntactical components and logic of [ITU-T Rec. X.500](https://www.itu.int/rec/T-REC-X.500). Though exclusive to directory services, it is not exclusive to LDAP.

## Intended Audience

As mentioned earlier, this package is low-level in nature. It is not designed for end users (i.e.: directory users or professionals), but rather for anyone creating a low level directory service implementation using Go.

## Dependencies

This package relies upon the following packages from the standard library:

  - `encoding/asn1`
  - `encoding/binary`
  - `encoding/base64`
  - `encoding/hex`
  - `errors`
  - `fmt`<sup><sup>†</sup></sup>
  - `math/big`
  - `os`
  - `reflect`<sup><sup>††</sup></sup>
  - `regexp`<sup><sup>†††</sup></sup>
  - `sort`
  - `strconv`
  - `strings`
  - `testing`
  - `time`
  - `unicode`
  - `unicode/utf8`
  - `unicode/utf16`

<sup>
  <sup><b>†</b>   - used ONLY for testing/examples</sup><br>
  <sup><b>††</b>  - very limited use</sup><br>
  <sup><b>†††</b> - only used for custom syntaxes implemented through the X-PATTERN eXtension</sup><br>
</sup>
<br>

This package relies upon the following third-party packages:

  - [`uuid`](https://github.com/google/uuid)
  - [`asn1-ber`](https://github.com/go-asn1-ber/asn1-ber)
  - [`objectid`](https://github.com/JesseCoretta/go-objectid)
  - [`shifty`](https://github.com/JesseCoretta/go-shifty)

## Supported Matching Rules

The following matching rules are supported by this package at this time.  More will be added in the future:

  - `bitStringMatch` ([RFC 4517 § 4.2.1](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.1))
  - `booleanMatch` ([RFC 4517 § 4.2.2](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.2))
  - `caseExactIA5Match` ([RFC 4517 § 4.2.3](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.3))
  - `caseExactMatch` ([RFC 4517 § 4.2.4](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.4))
  - `caseExactOrderingMatch` ([RFC 4517 § 4.2.5](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.5))
  - `caseExactSubstringsMatch` ([RFC 4517 § 4.2.6](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.6))
  - `caseIgnoreIA5Match` ([RFC 4517 § 4.2.7](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.7))
  - `caseIgnoreIA5SubstringsMatch` ([RFC 4517 § 4.2.8](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.8))
  - `caseIgnoreListMatch` ([RFC 4517 § 4.2.9](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.9))
  - `caseIgnoreListSubstringsMatch` ([RFC 4517 § 4.2.10](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.10))
  - `caseIgnoreMatch` ([RFC 4517 § 4.2.11](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.11))
  - `caseIgnoreOrderingMatch` ([RFC 4517 § 4.2.12](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.12))
  - `caseIgnoreSubstringsMatch` ([RFC 4517 § 4.2.13](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.13))
  - `directoryStringFirstComponentMatch` ([RFC 4517 § 4.2.14](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.14))
  - `distinguishedNameMatch` ([RFC 4517 § 4.2.15](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.15))
  - `generalizedTimeMatch` ([RFC 4517 § 4.2.16](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.16))
  - `generalizedTimeOrderingMatch` ([RFC 4517 § 4.2.17](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.17))
  - `integerFirstComponentMatch` ([RFC 4517 § 4.2.18](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.18))
  - `integerMatch` ([RFC 4517 § 4.2.19](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.19))
  - `integerOrderingMatch` ([RFC 4517 § 4.2.20](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.20))
  - `keywordMatch` ([RFC 4517 § 4.2.21](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.21))
  - `numericStringMatch` ([RFC 4517 § 4.2.22](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.22))
  - `numericStringOrderingMatch` ([RFC 4517 § 4.2.23](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.23))
  - `numericStringSubstringsMatch` ([RFC 4517 § 4.2.24](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.24))
  - `objectIdentifierFirstComponentMatch` ([RFC 4517 § 4.2.25](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.25))
  - `objectIdentifierMatch` ([RFC 4517 § 4.2.26](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.26))
  - `octetStringMatch` ([RFC 4517 § 4.2.27](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.27))
  - `octetStringOrderingMatch` ([RFC 4517 § 4.2.28](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.28))
  - `telephoneNumberMatch` ([RFC 4517 § 4.2.29](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.29))
  - `telephoneNumberSubstringsMatch` ([RFC 4517 § 4.2.30](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.30))
  - `uniqueMemberMatch` ([RFC 4517 § 4.2.31](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.31))
  - `wordMatch` ([RFC 4517 § 4.2.32](https://www.rfc-editor.org/rfc/rfc4517#section-4.2.32))

## Supported Syntaxes

The following syntaxes are supported by this package at this time.  More will be added in the future:

  - Attribute Type Description ([RFC 4512 § 4.1.2](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2) and [RFC 4517 § 3.3.1](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.1))
  - Bit String ([RFC 4517 § 3.3.2](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2))
  - Boolean ([RFC 4517 § 3.3.3](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3))
  - Boot Parameter ([RFC 2307 § 2.4](https://datatracker.ietf.org/doc/html/rfc2307#section-2.4))
  - Country String ([RFC 4517 § 3.3.4](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4))
  - Delivery Method ([RFC 4517 § 3.3.5](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.5))
  - Directory String ([RFC 4517 § 3.3.6](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.6) and [ITU-T Rec. X.520 § clause 2.6](https://www.itu.int/rec/T-REC-X.520))
    - TeletexString ([ITU-T Rec. T.61](https://www.itu.int/rec/T-REC-T.61))
    - PrintableString ([ITU-T Rec. X.680](https://www.itu.int/rec/T-REC-X.680) and [RFC 4517 § 3.3.29](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29))
    - BMPString ([ITU-T Rec. X.680](https://www.itu.int/rec/T-REC-X.680))
    - UniversalString ([ITU-T Rec. X.680](https://www.itu.int/rec/T-REC-X.680))
    - UTF8String ([ITU-T Rec. X.680](https://www.itu.int/rec/T-REC-X.680))
  - DIT Content Rule Description ([RFC 4512 § 4.1.6](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6) and [RFC 4517 § 3.3.7](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.7))
  - DIT Structure Rule Description ([RFC 4512 § 4.1.7.1](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6) and [RFC 4517 § 3.3.8](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.8))
  - DN ([RFC 4517 § 3.3.9](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.9))
  - Enhanced Guide ([RFC 4517 § 3.3.10](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10))
  - Facsimile Telephone Number ([RFC 4517 § 3.3.11](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11))
  - Fax ([RFC 4517 § 3.3.12](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.12))
  - Filter ([RFC 4515 § 2](https://datatracker.ietf.org/doc/html/rfc4515#section-2) and [RFC 4515 § 3](https://datatracker.ietf.org/doc/html/rfc4515#section-3))
  - Generalized Time ([RFC 4517 § 3.3.13](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13))
  - Guide ([RFC 4517 § 3.3.14](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.14))
  - IA5 String ([RFC 4517 § 3.3.15](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.15))
  - Integer ([RFC 4517 § 3.3.16](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.16))
  - JPEG ([RFC 4517 § 3.3.17](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.17))
  - LDAP Syntax Description ([RFC 4512 § 4.1.5](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5) and [RFC 4517 § 3.3.18](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.18))
  - Matching Rule Description ([RFC 4512 § 4.1.3](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3) and [RFC 4517 § 3.3.19](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.19))
  - Name and Optional UID ([RFC 4517 § 3.3.21](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21))
  - Name Form Description ([RFC 4512 § 4.1.7.2](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.2) and [RFC 4517 § 3.3.22](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.22))
  - Netscape Access Control Instruction Version 3.0 (proprietary)
  - NIS Netgroup Triple ([RFC 2307 § 2.4](https://datatracker.ietf.org/doc/html/rfc2307#section-2.4))
  - Numeric String ([RFC 4517 § 3.3.23](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23))
  - Object Class Description ([RFC 4512 § 4.1.1](https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1) and [RFC 4517 § 3.3.24](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.24))
  - Octet String ([RFC 4517 § 3.3.25](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.25))
  - OID ([RFC 4517 § 3.3.26](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.26))
  - Other Mailbox ([RFC 4517 § 3.3.27](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.27))
  - Postal Address ([RFC 4517 § 3.3.28](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.28))
  - Substring Assertion ([RFC 4517 § 3.3.30](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30))
  - Subtree Specification ([Appendix A, RFC 3672](https://datatracker.ietf.org/doc/html/rfc3672#appendix-A))
  - Telephone Number ([RFC 4517 § 3.3.31](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.31))
  - Teletex Terminal Identifier ([RFC 4517 § 3.3.32](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.32))
  - Telex Number ([RFC 4517 § 3.3.33](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.33))
  - UTC Time ([RFC 4517 § 3.3.34](https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.34))
  - UUID ([RFC 4530 § 2.1](https://datatracker.ietf.org/doc/html/rfc4530#section-2.1))

