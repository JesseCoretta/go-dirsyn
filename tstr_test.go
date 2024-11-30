package dirsyn

import (
	"fmt"
	"testing"
)

func ExampleTeletexString_IsZero() {
	var tel TeletexString
	fmt.Println(tel.IsZero())
	// Output: true
}

func TestTeletexString_codecov(t *testing.T) {
	teletexString(`X`)
	teletexString(``)
	marshalTeletexString([]byte{0x1E, 0x3, 0x2, 0x3, 0x5})
}
