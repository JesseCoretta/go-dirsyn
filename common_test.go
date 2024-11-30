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

	isStruct(struct{}{})
	isStruct(struct{ A string }{A: ``})

	strInSlice(`this`, []string{`is`, `data`}, true)
	strInSlice(`this`, []string{`is`, `data`}, false)

	isNumber(``)
	isNumber(`01A`)
	isNumber(`01999`)

	_, _ = assertString(``, 0, "name")
	_, _ = assertString([]byte{0x0}, 1, "name")

	_, _ = caseIgnoreMatch(`this`, `That`)
	_, _ = caseExactMatch(`That`, `That`)
	_, _ = caseExactMatch(`That`, struct{}{})
	_, _ = caseExactMatch(struct{}{}, nil)
	_, _ = caseIgnoreOrderingMatch(`abc`, `xyz`)
	_, _ = caseIgnoreOrderingMatch(`abc`, `abc`)
	_, _ = caseIgnoreOrderingMatch(`abc`, nil)
	_, _ = caseIgnoreOrderingMatch(nil, `xyz`)
	_, _ = caseExactOrderingMatch(`abc`, `xyz`)
	_, _ = caseExactOrderingMatch(`abc`, `abc`)
	_, _ = caseExactOrderingMatch(`abc`, nil)
	_, _ = caseExactOrderingMatch(nil, `xyz`)
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
