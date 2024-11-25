package dirsyn

/*
time.go implements all temporal syntaxes and matching rules -- namely
those for Generalized Time and the (deprecated) UTC Time.
*/

import "time"

/*
GeneralizedTime aliases an instance of [time.Time] to implement [§ 3.3.13
of RFC 4517]:

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

[§ 3.3.13 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13
*/
type GeneralizedTime time.Time

/*
GeneralizedTime returns an instance of [GeneralizedTime] alongside an error.
*/
func (r RFC4517) GeneralizedTime(x any) (gt GeneralizedTime, err error) {
	var (
		format string = `20060102150405` // base format
		diff   string = `-0700`
		base   string
		raw    string
	)

	if raw, err = assertString(x, 15, "Generalized Time"); err != nil {
		return
	}
	raw = chopZulu(raw)

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
	if format, err = genTimeFracDiffFormat(raw, base, diff, format); err != nil {
		return
	}

	var _gt time.Time
	if _gt, err = time.Parse(format, raw); err == nil {
		gt = GeneralizedTime(_gt)
	}

	return
}

// Handle generalizedTime fractional component (up to six (6) digits)
func genTimeFracDiffFormat(raw, base, diff, format string) (string, error) {
	var err error

	if base[0] == '.' || base[0] == ',' {
		format += string(".")
		for fidx, ch := range base[1:] {
			if fidx > 6 {
				err = errorTxt(`Fraction exceeds Generalized Time fractional limit`)
			} else if isDigit(ch) {
				format += `0`
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

	return format, err
}

/*
String returns the string representation of the receiver instance.
*/
func (r GeneralizedTime) String() string {
	return time.Time(r).Format(`20060102150405`) + `Z`
}

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r GeneralizedTime) Cast() time.Time {
	return time.Time(r)
}

/*
Eq returns a Boolean value indicative of an equality matching rule
assertion between receiver r and input x.
*/
func (r GeneralizedTime) Eq(x any) bool {
	return timeMatch(r, x, 0)
}

/*
Ne returns a Boolean value indicative of a negated equality matching
rule assertion between receiver r and input x.
*/
func (r GeneralizedTime) Ne(x any) bool {
	return timeMatch(r, x, -1)
}

/*
Ge returns a Boolean value indicative of a greaterOrEqual matching rule
assertion between receiver r and input x.
*/
func (r GeneralizedTime) Ge(x any) bool {
	return timeMatch(r, x, 1)
}

/*
Gt returns a Boolean value indicative of a greaterThan matching rule
assertion between receiver r and input x.  Strictly speaking, this
is not an official component, but is present for convenience.
*/
func (r GeneralizedTime) Gt(x any) bool {
	return timeMatch(r, x, 3)
}

/*
Le returns a Boolean value indicative of a lessOrEqual matching rule
assertion between receiver r and input x.
*/
func (r GeneralizedTime) Le(x any) bool {
	return timeMatch(r, x, 2)
}

/*
Lt returns a Boolean value indicative of a lessThan matching rule
assertion between receiver r and input x.  Strictly speaking, this
is not an official component, but is present for convenience.
*/
func (r GeneralizedTime) Lt(x any) bool {
	return timeMatch(r, x, 4)
}

/*
Deprecated: UTCTime implements [§ 3.3.34 of RFC 4517].

	UTCTime         = year month day hour minute [ second ] [ u-time-zone ]
	u-time-zone     = %x5A  ; "Z"
	                  / u-differential
	u-differential  = ( MINUS / PLUS ) hour minute

Use instances of [GeneralizedTime] instead.

[§ 3.3.34 of RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.34
*/
type UTCTime time.Time

/*
String returns the string representation of the receiver instance.
*/
func (r UTCTime) String() string {
	return time.Time(r).Format(`0601021504`) + `Z`
}

/*
Cast unwraps and returns the underlying instance of [time.Time].
*/
func (r UTCTime) Cast() time.Time {
	return time.Time(r)
}

/*
Eq returns a Boolean value indicative of an equality matching rule
assertion between receiver r and input x.
*/
func (r UTCTime) Eq(x any) bool {
	return timeMatch(r, x, 0)
}

/*
Ne returns a Boolean value indicative of a negated equality matching
rule assertion between receiver r and input x.
*/
func (r UTCTime) Ne(x any) bool {
	return timeMatch(r, x, -1)
}

/*
Ge returns a Boolean value indicative of a greaterOrEqual matching rule
assertion between receiver r and input x.
*/
func (r UTCTime) Ge(x any) bool {
	return timeMatch(r, x, 1)
}

/*
Gt returns a Boolean value indicative of a greaterThan matching rule
assertion between receiver r and input x.  Strictly speaking, this
is not an official component, but is present for convenience.
*/
func (r UTCTime) Gt(x any) bool {
	return timeMatch(r, x, 3)
}

/*
Le returns a Boolean value indicative of a lessOrEqual matching rule
assertion between receiver r and input x.
*/
func (r UTCTime) Le(x any) bool {
	return timeMatch(r, x, 2)
}

/*
Lt returns a Boolean value indicative of a lessThan matching rule
assertion between receiver r and input x.  Strictly speaking, this
is not an official component, but is present for convenience.
*/
func (r UTCTime) Lt(x any) bool {
	return timeMatch(r, x, 4)
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
	)

	switch tv := x.(type) {
	case string:
		raw = chopZulu(tv)

		if len(raw) < 10 {
			err = errorBadLength(`UTC Time`, len(tv))
			break
		}
		utc, err = uTCHandler(raw, sec, diff, format)
	default:
		err = errorBadType(`UTC Time`)
	}

	return

}

func chopZulu(raw string) string {
	if zulu := raw[len(raw)-1] == 'Z'; zulu {
		raw = raw[:len(raw)-1]
	}

	return raw
}

func uTCHandler(raw, sec, diff, format string) (utc UTCTime, err error) {
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

/*
timeMatch implements [§ 4.2.16] and [§ 4.2.17] of RFC4517.

[§ 4.2.16 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.16
[§ 4.2.17 of RFC 4517]: https://www.rfc-editor.org/rfc/rfc4517#section-4.2.17
*/
func timeMatch(rcv, assert any, typ int) (result bool) {
	var c time.Time
	var utc bool

	switch tv := rcv.(type) {
	case GeneralizedTime:
		c = tv.Cast().UTC()
	case UTCTime:
		c = tv.Cast().UTC()
		utc = true
	}

	var funk func(time.Time) bool
	switch typ {
	case -1:
		funk = func(thyme time.Time) bool {
			return !c.Equal(thyme)
		}
	case 0:
		funk = func(thyme time.Time) bool {
			return c.Equal(thyme)
		}
	case 1:
		funk = func(thyme time.Time) bool {
			return c.After(thyme)
		}
	case 2:
		funk = func(thyme time.Time) bool {
			return c.Before(thyme)
		}
	case 3:
		funk = func(thyme time.Time) bool {
			return c.Equal(thyme) || c.After(thyme)
		}
	case 4:
		funk = func(thyme time.Time) bool {
			return c.Equal(thyme) || c.Before(thyme)
		}
	}

	result = compareTimes(assert, utc, funk)

	return
}

func compareTimes(assert any, utc bool, funk func(time.Time) bool) (result bool) {
	var s RFC4517

	switch tv := assert.(type) {
	case GeneralizedTime:
		result = funk(tv.Cast())
	case UTCTime:
		result = funk(tv.Cast())
	case time.Time:
		result = funk(tv)
	default:
		if utc {
			d, err := s.UTCTime(tv)
			result = funk(d.Cast()) && err == nil
		} else {
			d, err := s.GeneralizedTime(tv)
			result = funk(d.Cast()) && err == nil
		}
	}

	return
}
