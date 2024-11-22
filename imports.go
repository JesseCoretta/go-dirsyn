package dirsyn

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
)

var (
	fmtInt   func(int64, int) string                   = strconv.FormatInt
	fmtUint  func(uint64, int) string                  = strconv.FormatUint
	atoi     func(string) (int, error)                 = strconv.Atoi
	itoa     func(int) string                          = strconv.Itoa
	cntns    func(string, string) bool                 = strings.Contains
	newErr   func(string) error                        = errors.New
	fields   func(string) []string                     = strings.Fields
	trimS    func(string) string                       = strings.TrimSpace
	trimR    func(string, string) string               = strings.TrimRight
	trimPfx  func(string, string) string               = strings.TrimPrefix
	trimSfx  func(string, string) string               = strings.TrimSuffix
	hasPfx   func(string, string) bool                 = strings.HasPrefix
	hasSfx   func(string, string) bool                 = strings.HasSuffix
	join     func([]string, string) string             = strings.Join
	split    func(string, string) []string             = strings.Split
	splitN   func(string, string, int) []string        = strings.SplitN
	idxr     func(string, rune) int                    = strings.IndexRune
	repAll   func(string, string, string) string       = strings.ReplaceAll
	eqf      func(string, string) bool                 = strings.EqualFold
	puint    func(string, int, int) (uint64, error)    = strconv.ParseUint
	fuint    func(uint64, int) string                  = strconv.FormatUint
	hexdec   func(string) ([]byte, error)              = hex.DecodeString
	enchex   func([]byte) string                       = hex.EncodeToString
	asn1m    func(any) ([]byte, error)                 = asn1.Marshal
	asn1mp   func(any, string) ([]byte, error)         = asn1.MarshalWithParams
	asn1um   func([]byte, any) ([]byte, error)         = asn1.Unmarshal
	asn1ump  func([]byte, any, string) ([]byte, error) = asn1.UnmarshalWithParams
	stridx   func(string, string) int                  = strings.Index
	strlidx  func(string, string) int                  = strings.LastIndex
	strcnt   func(string, string) int                  = strings.Count
	trim     func(string, string) string               = strings.Trim
	uc       func(string) string                       = strings.ToUpper
	lc       func(string) string                       = strings.ToLower
	readFile func(string) ([]byte, error)              = os.ReadFile
)

func newStrBuilder() strings.Builder {
	return strings.Builder{}
}

func escapeString(x string) (esc string) {
	if len(x) > 0 {
		bld := newStrBuilder()
		for _, z := range x {
			if z > maxASCII {
				for _, c := range []byte(string(z)) {
					bld.WriteString(`\`)
					bld.WriteString(fuint(uint64(c), 16))
				}
			} else {
				bld.WriteRune(z)
			}
		}

		esc = bld.String()
	}

	return
}

func hexEncode(x any) string {
	var r string
	switch tv := x.(type) {
	case string:
		r = tv
	case []byte:
		r = string(tv)
	default:
		return ``
	}

	e := newStrBuilder()
	for _, c := range r {
		for _, b := range []byte(string(c)) {
			e.WriteString("\\")
			e.WriteString(fuint(uint64(b), 16))
		}
	}
	return e.String()
}

func hexDecode(x any) string {
	var r string
	switch tv := x.(type) {
	case string:
		r = tv
	case []byte:
		r = string(tv)
	default:
		return ``
	}

	d := newStrBuilder()
	length := len(r)

	for i := 0; i < length; i++ {
		if r[i] == '\\' && i+3 <= length {
			b, err := hexdec(r[i+1 : i+3])
			if err != nil {
				return ``
			} else if !isHex(rune(r[i+1])) || !isHex(rune(r[i+2])) {
				return ``
			}
			d.Write(b)
			i += 2
		} else {
			d.WriteString(string(r[i]))
		}
	}

	return d.String()
}

func isBase64(x any) (is bool) {
	var raw string
	switch tv := x.(type) {
	case string:
		raw = tv
	case []byte:
		raw = string(tv)
	default:
		return
	}

	_, err := base64.StdEncoding.DecodeString(raw)
	is = err == nil

	return
}

func b64dec(enc []byte) (dec []byte, err error) {
	dec = make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
	_, err = base64.StdEncoding.Decode(dec, enc)
	return
}
