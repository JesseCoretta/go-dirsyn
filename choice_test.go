package dirsyn

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

// intChoice implements the Choice interface for an ASN.1 INTEGER.
type intChoice int

func (i intChoice) ChoiceTag() int {
	// The ASN.1 tag for INTEGER (DER) is 2.
	return asn1.TagInteger
}

func (i intChoice) AcceptsTag(tag int) bool {
	return tag == 2
}

func (i *intChoice) DecodeChoice(raw asn1.RawValue) error {
	// Decode into the integer.
	// Note: since "i" is a pointer to intChoice, it will be set appropriately.
	_, err := asn1.Unmarshal(raw.FullBytes, i)
	return err
}

// stringChoice implements the Choice interface for a PrintableString.
// (PrintableString is typically assigned tag 19 in DER.)
type stringChoice string

func (s stringChoice) ChoiceTag() int {
	return 19
}

func (i stringChoice) AcceptsTag(tag int) bool {
	return tag == asn1.TagOctetString || tag == asn1.TagUTF8String ||
		tag == asn1.TagPrintableString || tag == asn1.TagIA5String
}

func (s *stringChoice) DecodeChoice(raw asn1.RawValue) error {
	// Decode into a temporary string and assign it.
	var tmp string
	_, err := asn1.Unmarshal(raw.FullBytes, &tmp)
	if err == nil {
		*s = stringChoice(tmp)
	}
	return err
}

func ExampleChoice() {
	// Get the ASN.1 DER encoding of integer 123456.
	encodedValue, err := asn1.Marshal(123456)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create our choice registry for this
	// ASN.1 CHOICE scenario.
	reg := make(Choices, 0)

	// These are private test types, assume they
	// are used-defined Choice qualifiers.
	reg.Register(new(stringChoice))
	reg.Register(new(intChoice))
	//reg.Register(new(...)) // other Choice qualifiers
	//reg.Register(new(...)) // defined by the user.

	var ch Choice
	if ch, err = reg.Unmarshal(encodedValue); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%T: %d", ch, (*ch.(*intChoice)))
	// Output: *dirsyn.intChoice: 123456
}

func TestChoice_Int(t *testing.T) {
	encodedInt, _ := asn1.Marshal(12345)

	reg := make(Choices, 0)
	reg.Register(new(stringChoice))
	reg.Register(new(intChoice))

	if ch, err := reg.Unmarshal(encodedInt); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if _, ok := ch.(*intChoice); !ok {
		t.Errorf("%s failed: expected *intChoice, got:  %T", t.Name(), ch)
	}
}

func TestChoice_String(t *testing.T) {
	encodedStr, _ := asn1.Marshal("Hello, ASN.1!")

	reg := make(Choices, 0)
	reg.Register(new(intChoice))
	reg.Register(new(stringChoice))

	if ch, err := reg.Unmarshal(encodedStr); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if _, ok := ch.(*stringChoice); !ok {
		t.Errorf("%s failed:\n\twant: *stringChoice\n\tgot:  %T", t.Name(), ch)
	}
}

func TestChoice_codecov(t *testing.T) {
	str := new(stringChoice)
	intg := new(intChoice)
	var reg Choices = Choices{str, intg}
	_, _ = reg.Unmarshal([]byte{})
	_, _ = reg.Unmarshal([]byte{})
	_, _ = reg.Unmarshal([]byte{0x7f})
	_, _ = reg.Unmarshal([]byte{0x2, 0x3, 0x1, 0xe2, 0x40, 0xff, 0xff, 0x0})

	_ = errEmptyChoice(nil, 2)
}
