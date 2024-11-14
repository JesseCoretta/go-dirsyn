package dirsyn

import (
	"testing"
)

func TestSubstringAssertion(t *testing.T) {
	var r RFC4517
	for idx, raw := range []string{
		`substring*substring`,
		`substri\\\\n*stringy`,
		`*substring*substring*`,
		`substr\\\\*ing*end`,
		`substring*substring*substring`,
		`substr\\*ing*end`,
	} {
		if err := r.SubstringAssertion(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestUUID(t *testing.T) {
	var r RFC4530

	for idx, raw := range []string{
		`f81d4fae-7dec-11d0-a765-00a0c91e6bf6`,
	} {
		if err := r.UUID(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestJPEG(t *testing.T) {
	var r RFC4517
	if err := r.JPEG(testJPEGData); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

/*
testJPEGData contains a byte sequence of a heavily truncated JPEG file (my github avatar).

Envelope-wise, this is a valid byte block and is used purely for unit testing, but really
only contains a couple of pixels worth of "image data". Even a heavily scaled-down -- but
complete -- JPEG block was too big to put in its raw byte form as in-line code.
*/
var testJPEGData []byte = []byte{
	0xff, 0xd8, 0xff, 0xe0, 0x0, 0x10,
	0x4a, 0x46, 0x49, 0x46, 0x0, 0x1,
	0x1, 0x1, 0xac, 0xff, 0xd9}
