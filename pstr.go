package dirsyn

/*
PrintableString implements [§ 3.3.29 of RFC 4517]:

	PrintableCharacter = ALPHA / DIGIT / SQUOTE / LPAREN / RPAREN /
	                     PLUS / COMMA / HYPHEN / DOT / EQUALS /
	                     SLASH / COLON / QUESTION / SPACE
	PrintableString    = 1*PrintableCharacter

From [§ 1.4 of RFC 4512]:

	ALPHA   = %x41-5A / %x61-7A    ; "A"-"Z" / "a"-"z"
	DIGIT   = %x30 / LDIGIT        ; "0"-"9"
	SQUOTE  = %x27                 ; single quote ("'")
	SPACE   = %x20                 ; space (" ")
	LPAREN  = %x28                 ; left paren ("(")
	RPAREN  = %x29                 ; right paren (")")
	PLUS    = %x2B                 ; plus sign ("+")
	COMMA   = %x2C                 ; comma (",")
	HYPHEN  = %x2D                 ; hyphen ("-")
	DOT     = %x2E                 ; period (".")
	EQUALS  = %x3D                 ; equals sign ("=")

From [§ 3.2 of RFC 4517]:

	SLASH     = %x2F               ; forward slash ("/")
	COLON     = %x3A               ; colon (":")
	QUESTION  = %x3F               ; question mark ("?")

[§ 3.3.29 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29
[§ 3.2 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.2
[§ 1.4 of RFC 4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-1.4
*/
type PrintableString string

/*
String returns the string representation of the receiver instance.
*/
func (r PrintableString) String() string {
	return string(r)
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r PrintableString) IsZero() bool { return len(r) == 0 }

func printableString(x any) (result Boolean) {
	_, err := marshalPrintableString(x)
	result.Set(err == nil)
	return
}

/*
PrintableString returns an error following an analysis of x in the context
of a [PrintableString].
*/
func (r RFC4517) PrintableString(x any) (PrintableString, error) {
	return marshalPrintableString(x)
}

func marshalPrintableString(x any) (ps PrintableString, err error) {
	var raw string

	switch tv := x.(type) {
	case PrintableString:
		ps, err = marshalPrintableString(tv.String())
		return
	case string:
		if len(tv) == 0 {
			err = errorBadLength("Printable String", 0)
			return
		}
		raw = tv
	case []byte:
		ps, err = marshalPrintableString(string(tv))
		return
	default:
		err = errorBadType("Printable String")
		return
	}

	if !checkPrintableStringChars(raw) {
		err = errorTxt("Invalid Printable String: " + raw)
		return
	}

	for _, ch := range raw {
		char := rune(ch)
		if !isTelephoneNumberChar(char) {
			err = errorBadType("Invalid Telephone Number character: " + string(char))
			return
		}
	}

	ps = PrintableString(raw)

	return
}

func checkPrintableStringChars(raw string) (is bool) {
	if len(raw) == 0 {
		return
	}

	for i := 0; i < len(raw); i++ {
		r := rune(raw[i])
		if !(isAlphaNumeric(r) || runeInSlice(r, printableStringRunes)) {
			return
		}
	}

	is = true

	return
}

var printableStringChars []rune = []rune{
	'\'', '(', ')', '+', ',', '-', '.', '=', '/', ':', '?', ' ',
}
