package dirsyn

import (
	"os"
	"testing"
)

func TestMisc_codecov(t *testing.T) {

	b64dec([]byte{0x0, 0x1, 0x2, 0xff})
	isBase64([]byte{0x0, 0x1, 0x2, 0xff})
	isBase64(``)
	isBase64(struct{}{})

	hexEncode(``)
	hexEncode(nil)
	hexEncode([]byte{})
	hexEncode(`ABC`)
	hexEncode(`##`)

	hexDecode(``)
	hexDecode(nil)
	hexDecode([]byte{})
	hexDecode(`ABC`)
	hexDecode(`\u00XH`)
	hexDecode(`\zz`)
	hexDecode(`##`)
}

func writeTemporaryFile(name string, content []byte) (file *os.File, err error) {
	file, err = os.CreateTemp("", name)
	if err != nil {
		return
	}

	// Write data to the temporary file
	_, err = file.Write(content)
	return
}

func deleteTemporaryFile(file *os.File) error {
	return os.Remove(file.Name())
}
