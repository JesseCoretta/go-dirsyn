package dirsyn

import (
	"fmt"
	"testing"
)

func TestUUIDMatch(t *testing.T) {
	a1 := `23c4bc48-b82d-4091-a3c2-c1a62502d318`
	a2 := `3918e81f-1278-4573-9ae8-8a650310e54c`

	var u1, u2 UUID
	var err error

	if u1, err = marshalUUID(a1); err != nil {
		t.Errorf("%s [ordering] failed: %v", t.Name(), err)
		return
	}

	if u2, err = marshalUUID(a2); err != nil {
		t.Errorf("%s [ordering] failed: %v", t.Name(), err)
		return
	}

	var result Boolean
	if result, err = uuidOrderingMatch(u1, u2, LessOrEqual); err != nil {
		t.Errorf("%s [ordering] failed: %v", t.Name(), err)
		return
	}

	if !result.True() {
		t.Errorf("%s [ordering] failed: want %s, got %s", t.Name(), `TRUE`, result)
		return
	}

	if result, err = uuidMatch(u1, u2); err != nil {
		t.Errorf("%s [equality] failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s [equality] failed: want %s, got %s", t.Name(), `FALSE`, result)
		return
	}
}

func TestUUID(t *testing.T) {
	var r RFC4530

	// We can skimp on tests, since we're just wrapping
	// a call to Google's uuid.Parse function.
	for idx, raw := range []string{
		`f81d4fae-7dec-11d0-a765-00a0c91e6bf6`,
	} {
		if _, err := r.UUID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}

	// codecov
	r.UUID(`X`)
	r.UUID('X')
	r.UUID(struct{}{})
}

/*
This example demonstrates the means for converting a [UUID] instance to
an [Integer] instance.
*/
func ExampleUUID_Integer() {
	var r RFC4530
	u, err := r.UUID(`00be4308-0c89-1085-8ea0-0002a5d5fd2e`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", u.Integer())
	// Output: 987895962269883002155146617097157934
}
