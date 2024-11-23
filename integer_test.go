package dirsyn

import (
	"math/big"
	"testing"
)

func TestInteger(t *testing.T) {
	var r RFC4517

	for _, strint := range []any{
		`1`,
		0,
		-38458953,
		`4839058392687026702779083590780972360798625907867923470670934207967924076924`,
		-48398472378783,
		`-4839058392687026702779083590780972360798625907867923470670934207967924076924`,
	} {
		if i, err := r.Integer(strint); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
			return
		} else {
			var i2 Integer
			i2.SetBytes(i.Bytes())

			want := i.String()
			if got := i2.String(); got != want {
				t.Errorf("%s failed:\nwant: %s\ngot:  %s", t.Name(), want, got)
				return
			}
		}
	}
}

func TestInteger_codecov(t *testing.T) {
	var r RFC4517

	assertNumber(6)
	assertNumber(int8(6))
	assertNumber(int16(6))
	assertNumber(int32(6))
	assertNumber(int64(6))
	assertNumber(uint(6))
	assertNumber(uint8(6))
	assertNumber(uint16(6))
	assertNumber(uint32(6))
	assertNumber(uint64(6))
	assertNumber(struct{}{})
	assertInt(struct{}{})
	assertUint(struct{}{})

	i, _ := r.Integer(5)
	for _, strint := range []string{
		``,
		`~`,
		`-`,
		`abnfcjnsf`,
		`#885`,
	} {
		if _, err := r.Integer(strint); err == nil {
			t.Errorf("%s failed: expected error, got nil", t.Name())
			return
		}
	}

	i1, _ := r.Integer(4)
	i2, _ := r.Integer(5)
	i3, _ := r.Integer(6)

	i1.IsZero()
	_ = i1.String()

	bint1 := big.NewInt(int64(4))
	bint2 := big.NewInt(int64(5))
	bint3 := big.NewInt(int64(6))

	for idx, Bool := range []bool{
		!i.Eq(`~`),
		i.Eq(`5`),
		i.Eq(5),
		i.Eq(uint(5)),
		i.Eq(uint64(5)),
		i.Eq(bint2),
		i.Eq(i2),
		i.Ne(`#`),
		i.Ne(`4`),
		i.Ne(4),
		i.Ne(uint(4)),
		i.Ne(uint64(4)),
		i.Ne(bint1),
		i.Ne(i1),
		!i.Lt(`!`),
		i.Lt(`6`),
		i.Lt(6),
		i.Lt(uint(6)),
		i.Lt(uint64(6)),
		i.Lt(bint3),
		i.Lt(i3),
		!i.Le(`_`),
		i.Le(`6`),
		i.Le(6),
		i.Le(uint(6)),
		i.Le(uint64(6)),
		i.Le(bint3),
		i.Lt(i3),
		!i.Gt(`=`),
		i.Gt(`4`),
		i.Gt(4),
		i.Gt(uint(4)),
		i.Gt(uint64(4)),
		i.Gt(bint1),
		i.Gt(i1),
		!i.Ge(`@`),
		i.Ge(`4`),
		i.Ge(4),
		i.Ge(uint(4)),
		i.Ge(uint64(4)),
		i.Ge(bint1),
		i.Ge(i1),
	} {
		if !Bool {
			t.Errorf("%s[%d] failed:\nwant: %t\ngot:  %t",
				t.Name(), idx, true, Bool)
		}
	}
}
