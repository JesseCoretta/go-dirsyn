package dirsyn

import (
	"testing"
)

func TestBitString_codecov(t *testing.T) {
	_, _ = assertBitString([]byte{})
	_, _ = assertBitString(struct{}{})
}
