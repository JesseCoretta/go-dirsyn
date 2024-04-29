package dirsyn

import (
	"fmt"
)

/*
EnhancedGuide returns an error following an analysis of x in the context
of an Enhanced Guide.

From § 3.3.10 of RFC 4517:

	EnhancedGuide = object-class SHARP WSP criteria WSP
	                   SHARP WSP subset
	object-class  = WSP oid WSP
	subset        = "baseobject" / "oneLevel" / "wholeSubtree"

	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")
*/
func EnhancedGuide(x any) (err error) {
	var raw string
	switch tv := x.(type) {
	case string:
		if len(tv) == 0 {
			err = fmt.Errorf("Zero length Enhanced Guide value")
			return
		}
		raw = tv
	default:
		err = fmt.Errorf("Incompatible type '%T' for Enhanced Guide", tv)
		return
	}

	return
}

/*
Deprecated: Guide is OBSOLETE and is provided for historical support only;
use [EnhancedGuide] instead.

Guide returns an error following an analysis of x in the context of a Guide.

From § 3.3.14 of RFC 4517:

	Guide = [ object-class SHARP ] criteria

	object-class  = WSP oid WSP
	criteria   = and-term *( BAR and-term )
	and-term   = term *( AMPERSAND term )
	term       = EXCLAIM term /
	             attributetype DOLLAR match-type /
	             LPAREN criteria RPAREN /
	             true /
	             false
	match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
	true       = "?true"
	false      = "?false"
	BAR        = %x7C  ; vertical bar ("|")
	AMPERSAND  = %x26  ; ampersand ("&")
	EXCLAIM    = %x21  ; exclamation mark ("!")
*/
func Guide(x any) (err error) {
	return
}
