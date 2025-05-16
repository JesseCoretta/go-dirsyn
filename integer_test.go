package dirsyn

import (
	"fmt"
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

/*
This example demonstrates the means for converting an [Integer] instance
to a [UUID] instance.
*/
func ExampleInteger_UUID() {
	var r RFC4517
	i, err := r.Integer(`987895962269883002155146617097157934`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(i.UUID())
	// Output: 00be4308-0c89-1085-8ea0-0002a5d5fd2e
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

	for _, strint := range []string{
		``,
		`~`,
		`-`,
		`abnfcjnsf`,
		`#885`,
	} {
		if i, err := r.Integer(strint); err == nil {
			t.Errorf("%s failed: expected error, got nil", t.Name())
			return
		} else {
			i.Size()
			i.tag()
		}
	}

	i1, _ := r.Integer(4)
	//i2, _ := r.Integer(5)
	//i3, _ := r.Integer(6)

	i1.IsZero()
	_ = i1.String()

	//bint1 := big.NewInt(int64(4))
	//bint2 := big.NewInt(int64(5))
	//bint3 := big.NewInt(int64(6))

	//var err error

	var result Boolean
	// LessOrEqual
	result, _ = integerOrderingMatch(1001, 101, LessOrEqual) // <=
	if !result.False() {
		t.Errorf("%s [LE] failed:\nwant: %s\ngot:  %s",
			t.Name(), `FALSE`, result)
	}

	// GreaterOrEqual
	result, _ = integerOrderingMatch(10, 11, GreaterOrEqual) // >=
	if !result.True() {
		t.Errorf("%s [GE] failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
	}

	// Equal (via LE)
	result, _ = integerOrderingMatch(1, 1, LessOrEqual) // <= (==)
	if !result.True() {
		t.Errorf("%s [EQ] failed:\nwant: %s\ngot:  %s",
			t.Name(), `TRUE`, result)
	}

	isIntegerType(int32(3))
	isNegativeInteger(int(-3))
	isNegativeInteger(int8(-3))
	isNegativeInteger(int16(-3))
	isNegativeInteger(int32(-3))
	isNegativeInteger(int64(-3))

	castUint64(8)
	castUint64(uint(8))
	castUint64(uint8(3))
	castUint64(uint16(3))
	castUint64(uint32(33))
	castUint64(uint64(9))
	castUint64(struct{}{})

	castInt64(3)
	castInt64(int(8))
	castInt64(int8(3))
	castInt64(int16(3))
	castInt64(int32(33))
	castInt64(int64(9))
	castInt64(struct{}{})

	var ii Integer
	ii.SetBytes([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10,
	})
	ii.UUID()

	integerMatch(struct{}{}, 1)
	integerMatch(1, struct{}{})

	type FirstComponent struct {
		Field Integer
	}
	type BadFirstComponent struct {
		Field float32
	}

	bint, _ := assertNumber(3)

	fc := FirstComponent{i1}
	bc := BadFirstComponent{float32(1)}
	integerFirstComponentMatch(nil, fc)
	integerFirstComponentMatch(bc, fc)
	integerFirstComponentMatch(fc, nil)
	integerFirstComponentMatch(fc, 1)
	integerFirstComponentMatch(fc, bint)
	integerFirstComponentMatch(fc, struct{}{})
	integerFirstComponentMatch(fc, fc)
	integerFirstComponentMatch(struct{}{}, fc)
	integerFirstComponentMatch(struct{}{}, 1)
}
