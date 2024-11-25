package dirsyn

import (
	"testing"
)

func TestJPEG(t *testing.T) {
	var r RFC4517
	// TODO - add file reader (string) test using a
	// temporary file loaded with testJPEGData bytes.
	if err := r.JPEG(testJPEGData); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}

	// create temporary file
	file, err := writeTemporaryFile(t.Name(), testJPEGData)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// read jpeg from temporary file
	if err = r.JPEG(file.Name()); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// delete temporary file
	if err = deleteTemporaryFile(file); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	}
}

func TestJPEG_codecov(t *testing.T) {
	var r RFC4517
	r.JPEG([]uint8(`dGVzdGluZzEyMzR0ZXN0aW5nNTY3OA==`)) // "testing1234testing5678"
	r.JPEG(``)
	r.JPEG([]uint8{0x0})
	r.JPEG(nil)
	r.JPEG(testJPEGData[:len(testJPEGData)-1]) // truncate footer
}

/*
testJPEGData contains a byte sequence of a heavily truncated JPEG file (my github avatar).

Envelope-wise, this is a valid byte block and is used purely for unit testing, but really
only contains a couple of pixels worth of "image data". Even a heavily scaled-down -- but
complete -- JPEG block was too big to put in its raw byte form as in-line code.
*/
var testJPEGData []byte = []byte{
	0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10,
	0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
	0x01, 0x01, 0xac, 0xff, 0xd9}
