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

	_ = bool2str(true)
	_ = bool2str(false)

	hexDecode(``)
	hexDecode(nil)
	hexDecode([]byte{})
	hexDecode(`ABC`)
	hexDecode(`\u00XH`)
	hexDecode(`\zz`)
	hexDecode(`##`)

	condenseWHSP(`this has spaces`)
	condenseWHSP(rune(33))

	bitSize(nil)
	bitSize(&struct{}{})

	percentDecode(`%2f%%`)

	caseBasedOrderingMatch(`a`, `A`, true, LessOrEqual)
	caseBasedOrderingMatch(`a`, `A`, false, LessOrEqual)
	caseBasedOrderingMatch(`A`, `a`, true, LessOrEqual)
	caseBasedOrderingMatch(`A`, `a`, false, LessOrEqual)

	var eqa EqualityRuleAssertion
	eqa.isMatchingRuleAssertionFunction()

	var ssa SubstringsRuleAssertion
	ssa.isMatchingRuleAssertionFunction()

	var ord OrderingRuleAssertion
	ord.isMatchingRuleAssertionFunction()
	eqa.isMatchingRuleAssertionFunction()

	isAttributeDescriptor(``)
	isAttributeDescriptor(`_`)
	isAttributeDescriptor(`9a`)
	isAttributeDescriptor(`IZ`)
	isAttributeDescriptor(`@a`)
	isAttributeDescriptor(`l-`)
	isAttributeDescriptor(`l-@l`)

	isStruct(struct{}{})
	isStruct(struct{ A string }{A: ``})

	strInSlice(`this`, []string{`is`, `data`}, true)
	strInSlice(`this`, []string{`is`, `data`}, false)

	isAttribute("__")
	isAttribute("l")
	isAttribute("c_n")
	isAttribute("5.6.7.8")

	isNumber(``)
	isNumber(`01A`)
	isNumber(`01999`)

	_, _ = assertString(``, 0, "name")
	_, _ = assertString([]byte{0x0}, 1, "name")

	_, _ = caseIgnoreMatch(`this`, `That`)
	_, _ = caseExactMatch(`That`, `That`)
	_, _ = caseExactMatch(`That`, struct{}{})
	_, _ = caseExactMatch(struct{}{}, nil)
	_, _ = caseIgnoreOrderingMatch(`abc`, `xyz`, GreaterOrEqual)
	_, _ = caseIgnoreOrderingMatch(`abc`, `abc`, GreaterOrEqual)
	_, _ = caseIgnoreOrderingMatch(`abc`, nil, GreaterOrEqual)
	_, _ = caseIgnoreOrderingMatch(nil, `xyz`, GreaterOrEqual)
	_, _ = caseExactOrderingMatch(`abc`, `xyz`, GreaterOrEqual)
	_, _ = caseExactOrderingMatch(`abc`, `abc`, GreaterOrEqual)
	_, _ = caseExactOrderingMatch(`abc`, nil, GreaterOrEqual)
	_, _ = caseExactOrderingMatch(nil, `xyz`, GreaterOrEqual)
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
