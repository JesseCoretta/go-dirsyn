package dirsyn

import (
	"testing"
)

func TestASN1_codecov(t *testing.T) {
	sizeTagAndLength(1, 10)
	sizeTagAndLength(51, 10)
	sizeTagAndLength(51, 1009)

	sizeBase128Int(768)
}
