package dirsyn

/*
time.go implements all temporal syntaxes -- namely Generalized Time and
the (deprecated) UTC Time.
*/

import "time"

/*
GeneralizedTime aliases an instance of [time.Time] to implement § 3.3.13
of RFC 4517:

	GeneralizedTime = century year month day hour
	                     [ minute [ second / leap-second ] ]
	                     [ fraction ]
	                     g-time-zone

	century = 2(%x30-39) ; "00" to "99"
	year    = 2(%x30-39) ; "00" to "99"
	month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
	          / ( %x31 %x30-32 ) ; "10" to "12"
	day     =   ( %x30 %x31-39 )    ; "01" to "09"
	          / ( %x31-32 %x30-39 ) ; "10" to "29"
	          / ( %x33 %x30-31 )    ; "30" to "31"
	hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
	minute  = %x30-35 %x30-39                        ; "00" to "59"

	second      = ( %x30-35 %x30-39 ) ; "00" to "59"
	leap-second = ( %x36 %x30 )       ; "60"

	fraction        = ( DOT / COMMA ) 1*(%x30-39)
	g-time-zone     = %x5A  ; "Z"
	                  / g-differential
	g-differential  = ( MINUS / PLUS ) hour [ minute ]
	MINUS           = %x2D  ; minus sign ("-")
*/
type GeneralizedTime time.Time

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralizedTime) String() string {
	return time.Time(r).Format(`20060102150405`) + `Z`
}

/*
GeneralizedTime returns an error following an analysis of x in the context
of a Generalized Time value.
*/
func (r RFC4517) GeneralizedTime(x any) (gt GeneralizedTime, err error) {
	var (
		format string = `20060102150405` // base format
		diff   string = `-0700`
		base   string
		raw    string
		fidx   int
		zulu   bool
	)

	switch tv := x.(type) {
	case string:
		if len(tv) < 15 {
			err = errorBadLength(`Generalized Time`, len(tv))
			return
		}
		raw = tv
		if zulu = raw[len(raw)-1] == 'Z'; zulu {
			raw = raw[:len(raw)-1]
		}
	default:
		err = errorBadType(`Generalized Time`)
		return
	}

	// If we've got nothing left, must be zulu
	// without any fractional or differential
	// components
	if base = raw[14:]; len(base) == 0 {
		var _gt time.Time
		if _gt, err = time.Parse(format, raw); err == nil {
			gt = GeneralizedTime(_gt)
		}
		return
	}

	// Handle fractional component (up to six (6) digits)
	if base[0] == '.' || base[0] == ',' {
		var ch rune
		format += string(".")
		for fidx, ch = range base[1:] {
			if fidx > 6 {
				err = errorTxt(`Fraction exceeds Generalized Time fractional limit`)
				return
			} else if isDigit(ch) {
				format += string(ch)
				continue
			}
			break
		}
	}

	// Handle differential time, or bail out if not
	// already known to be zulu.
	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	var _gt time.Time
	if _gt, err = time.Parse(format, raw); err == nil {
		gt = GeneralizedTime(_gt)
	}

	return
}

/*
UTCTime implements § 3.3.34 of RFC 4517.

	UTCTime         = year month day hour minute [ second ] [ u-time-zone ]
	u-time-zone     = %x5A  ; "Z"
	                  / u-differential
	u-differential  = ( MINUS / PLUS ) hour minute

Note this type is deprecated; use [RFC4517.GeneralizedTime] instead.
*/
type UTCTime time.Time

/*
String returns the string representation of the receiver instance.
*/
func (r UTCTime) String() string {
	return time.Time(r).Format(`0601021504`) + `Z`
}

/*
Deprecated: UTCTime is intended for historical support only; use [GeneralizedTime]
instead.

UTCTime returns an error following an analysis of x in the context of a
(deprecated) UTC Time value.
*/
func (r RFC4517) UTCTime(x any) (utc UTCTime, err error) {
	var (
		format string = `0601021504` // base format
		sec    string = `05`
		diff   string = `-0700`
		raw    string
		zulu   bool
	)

	switch tv := x.(type) {
	case string:
		raw = tv
		if zulu = raw[len(raw)-1] == 'Z'; zulu {
			raw = raw[:len(raw)-1]
		}

		if len(raw) < 10 {
			err = errorBadLength(`UTC Time`, len(tv))
			return
		}
	default:
		err = errorBadType(`UTC Time`)
		return
	}

	var _utc time.Time

	switch len(raw) {
	case 10:
		// base time containing neither seconds
		// nor a differential.
		if _utc, err = time.Parse(format, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	case 12:
		// base time containing only seconds.
		if _utc, err = time.Parse(format+sec, raw); err == nil {
			utc = UTCTime(_utc)
		}
		return
	}
	format += sec

	// Handle differential component
	if raw[len(raw)-5] == '+' || raw[len(raw)-5] == '-' {
		format += diff
	}

	if _utc, err = time.Parse(format, raw); err == nil {
		utc = UTCTime(_utc)
	}

	return

}
