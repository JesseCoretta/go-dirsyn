package dirsyn

import (
	"encoding/asn1"
	"encoding/base64"
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
	asn1m    func(any) ([]byte, error)                 = asn1.Marshal
	asn1mp   func(any, string) ([]byte, error)         = asn1.MarshalWithParams
	asn1um   func([]byte, any) ([]byte, error)         = asn1.Unmarshal
	asn1ump  func([]byte, any, string) ([]byte, error) = asn1.UnmarshalWithParams
	stridx   func(string, string) int                  = strings.Index
	strlidx  func(string, string) int                  = strings.LastIndex
	strcnt   func(string, string) int                  = strings.Count
	trim     func(string, string) string               = strings.Trim
	uc       func(string) string                       = strings.ToUpper
	readFile func(string) ([]byte, error)              = os.ReadFile
)

func newStrBuilder() strings.Builder {
	return strings.Builder{}
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
