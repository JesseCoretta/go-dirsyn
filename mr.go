package dirsyn

/*
MatchingRuleAssertion defines a closure signature held by qualifying
function instances intended to implement a particular Matching Rule.

The semantics of the MatchingRuleAssertion are discussed in [§ 4.1 of
RFC 4517].

[§ 4.1 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.1
*/
type MatchingRuleAssertion func(any, any) Boolean

/*
OctetStringMatch implements [§ 4.2.27 of RFC 4517].

OID: 2.5.13.17.

[§ 4.2.27 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.27
*/
//func (r OctetStringMatch(a,b any) bool {
//        var raw []byte
//        var equals bool
//        switch tv := a.(type) {
//        case []byte:
//                if len(tv) == 0 {
//                        // zero length values are OK
//                        return len(r) == 0
//                }
//                raw = tv
//        case OctetString:
//                return r.Eq([]byte(tv))
//        case string:
//                raw = []byte(tv)
//        default:
//                return false
//        }
//
//        if equals = len(r) == len(raw); equals {
//                for i, b := range raw {
//                        if equals = raw[i] == b; !equals {
//                                break
//                        }
//                }
//        }
//
//        return equals
//}

/*
BitStringMatch returns a Boolean value indicative of a BitStringMatch
as described in [§ 4.2.1 of RFC 4517].

OID: 2.5.13.16

[§ 4.2.1 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.1
*/
//func (r RFC4517) BitStringMatch(a, b any) bool {
//        var abs, bbs BitString
//        var err error
//
//        if abs, err = assertBitString(a); err != nil {
//                return false
//        }
//
//        abytes := abs.Bytes
//        abits := abs.BitLength
//
//        if bbs, err = assertBitString(b); err != nil {
//                return false
//        }
//
//        bbytes := bbs.Bytes
//        bbits := bbs.BitLength
//
//        if namedBitList {
//                // Remove trailing zero bits
//                abits = stripTrailingZeros(abytes, abits)
//                bbits = stripTrailingZeros(bbytes, bbits)
//        }
//
//        // Check if both bit strings have the same number of bits
//        if abits != bbits {
//                return false
//        }
//
//        // Compare bit strings bitwise
//        for i := 0; i < len(abytes); i++ {
//                if abytes[i] != bbytes[i] {
//                        return false
//                }
//        }
//
//        return true
//}
//
//// stripTrailingZeros removes trailing zero bits and returns the new bit length
//func stripTrailingZeros(bytes []byte, bitLength int) (blen int) {
//        blen = bitLength
//        for i := len(bytes) - 1; i >= 0; i-- {
//                for bit := 0; bit < 8; bit++ {
//                        if (bytes[i] & (1 << bit)) != 0 {
//                                return blen
//                        }
//                        blen--
//                }
//        }
//
//        return
//}
//
//
//// TODO - figure out how to expose this properly
//func substringsMatchingRule(x any, caseIgnore ...bool) bool {
//        var value string
//        switch tv := x.(type) {
//        case string:
//                value = tv
//        case []byte:
//                value = string(tv)
//        case SubstringAssertion:
//                value = tv.String()
//        default:
//                return false
//        }
//
//        caseHandler := func(val string) string { return val }
//
//        if len(caseIgnore) > 0 {
//                if caseIgnore[0] {
//                        caseHandler = lc
//                }
//        }
//
//        value = caseHandler(value)
//        if r.Any == nil {
//                return false
//        }
//
//        if r.Initial != nil {
//                initialStr := caseHandler(string(r.Initial))
//                if !hasPfx(value, initialStr) {
//                        return false
//                }
//                value = trimPfx(value, initialStr)
//        }
//
//        anyStr := `*` + trim(caseHandler(string(r.Any)), `*`) + `*`
//        substrings := split(anyStr, "*")
//        for _, substr := range substrings {
//                index := stridx(value, substr)
//                if index == -1 {
//                        return false
//                }
//                value = value[index+len(substr):]
//        }
//
//        if r.Final != nil {
//                finalStr := caseHandler(string(r.Final))
//                if !hasSfx(value, finalStr) {
//                        return false
//                }
//                value = trimSfx(value, finalStr)
//        }
//
//        return true
//}

/*
Eq implements [§ 4.2.2 of RFC 4517].

OID: 2.5.13.13.

[§ 4.2.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-4.2.2
*/
//func (r Boolean) BooleanMatch(x any) (result bool) {
//        var s RFC4517
//        b, err := s.Boolean(x)
//        if err != nil {
//                return
//        }
//
//        if r.IsZero() && b.IsZero() {
//                // § 4.2.2
//                // "The rule evaluates to TRUE if and only
//                // if the attribute value and the assertion
//                // value are both TRUE or both FALSE."
//                //
//                // We return false because it didn't say
//                // anything about UNDEFINED. CMIIW.
//                result = false
//        } else if !r.IsZero() && !b.IsZero() {
//                result = r.bool == b.bool
//        }
//
//        return
//}
