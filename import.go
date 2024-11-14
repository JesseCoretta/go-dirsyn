package dirsyn

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
)

var (
	fmtInt  func(int64, int) string                   = strconv.FormatInt
	fmtUint func(uint64, int) string                  = strconv.FormatUint
	atoi    func(string) (int, error)                 = strconv.Atoi
	itoa    func(int) string                          = strconv.Itoa
	cntns   func(string, string) bool                 = strings.Contains
	newErr  func(string) error                        = errors.New
	fields  func(string) []string                     = strings.Fields
	trimS   func(string) string                       = strings.TrimSpace
	trimR   func(string, string) string               = strings.TrimRight
	trimPfx func(string, string) string               = strings.TrimPrefix
	trimSfx func(string, string) string               = strings.TrimSuffix
	hasPfx  func(string, string) bool                 = strings.HasPrefix
	hasSfx  func(string, string) bool                 = strings.HasSuffix
	join    func([]string, string) string             = strings.Join
	split   func(string, string) []string             = strings.Split
	splitN  func(string, string, int) []string        = strings.SplitN
	idxr    func(string, rune) int                    = strings.IndexRune
	repAll  func(string, string, string) string       = strings.ReplaceAll
	eqf     func(string, string) bool                 = strings.EqualFold
	puint   func(string, int, int) (uint64, error)    = strconv.ParseUint
	asn1m   func(any) ([]byte, error)                 = asn1.Marshal
	asn1mp  func(any, string) ([]byte, error)         = asn1.MarshalWithParams
	asn1um  func([]byte, any) ([]byte, error)         = asn1.Unmarshal
	asn1ump func([]byte, any, string) ([]byte, error) = asn1.UnmarshalWithParams
	stridx  func(string, string) int                  = strings.Index
	strcnt  func(string, string) int                  = strings.Count
	trim    func(string, string) string               = strings.Trim
)

func newStrBuilder() strings.Builder {
	return strings.Builder{}
}
