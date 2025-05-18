package dirsyn

import (
	"testing"
)

func TestX680_Enumerated(t *testing.T) {
	var names map[Enumerated]string = map[Enumerated]string{
		0: "nameZero",
		1: "nameOne",
		2: "nameTwo",
		3: "nameThree",
		4: "nameFour",
		5: "nameFive",
	}

	var limitedNames map[Enumerated]string = map[Enumerated]string{
		0: "nameZero",
	}

	var srcs Sources

	e, err := srcs.X680().Enumerated(5, names)
	if err != nil {
		t.Errorf("%s failed [Enumerated marshal]: %v", t.Name(), err)
		return
	}

	// coverages
	_ = e.Int()
	_, _ = srcs.X680().Enumerated(int32(5), names)
	_, _ = srcs.X680().Enumerated(2, rune(10))
	_, _ = srcs.X680().Enumerated()

	var der *DERPacket
	if der, err = srcs.X690().DER(e); err != nil {
		t.Errorf("%s failed [DER packet]: %v", t.Name(), err)
		return
	}

	tal, _ := der.TagAndLength()

	if err = derReadEnumerated(&e, der, tal, names); err != nil {
		t.Errorf("%s failed [DER read]: %v", t.Name(), err)
		return
	}

	der2, _ := srcs.X690().DER() // init empty receiver
	if _, err = derWriteEnumerated(der2, e); err != nil {
		t.Errorf("%s failed [DER write]: %v", t.Name(), err)
		return
	}

	derReadEnumerated(&e, der, TagAndLength{Tag: 10, Length: 100}, nil)
	der.SetOffset()
	for range []error{
		derReadEnumerated(&e, der, TagAndLength{}, limitedNames),
		derReadEnumerated(&e, der, TagAndLength{}, names),
		derReadEnumerated(&e, der, TagAndLength{}, nil),
		derReadEnumerated(&e, der, tal, limitedNames),
		derReadEnumerated(&e, der2, TagAndLength{Tag: 10}, nil),
		derReadEnumerated(&e, der2, TagAndLength{Tag: 10}, limitedNames),
	} {
		//if err != nil {
		//	t.Logf("ERR VIEW: %v\n", err)
		//}
	}
}
