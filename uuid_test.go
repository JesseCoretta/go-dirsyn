package dirsyn

import (
	"fmt"
	"testing"
)

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
