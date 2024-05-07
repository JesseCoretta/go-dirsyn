package dirsyn

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
)

var (
	fmtInt func(int64, int) string                = strconv.FormatInt
	newErr func(string) error                     = errors.New
	trimS  func(string) string                    = strings.TrimSpace
	hasPfx func(string, string) bool              = strings.HasPrefix
	hasSfx func(string, string) bool              = strings.HasSuffix
	join   func([]string, string) string          = strings.Join
	split  func(string, string) []string          = strings.Split
	idxr   func(string, rune) int                 = strings.IndexRune
	repAll func(string, string, string) string    = strings.ReplaceAll
	eqf    func(string, string) bool              = strings.EqualFold
	puint  func(string, int, int) (uint64, error) = strconv.ParseUint
	asn1m  func(any) ([]byte, error)              = asn1.Marshal
	asn1um func([]byte, any) ([]byte, error)      = asn1.Unmarshal
	stridx func(string, string) int               = strings.Index
	strcnt func(string, string) int               = strings.Count
	trim   func(string, string) string            = strings.Trim
)

func newStrBuilder() strings.Builder {
	return strings.Builder{}
}
