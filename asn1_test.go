package dirsyn

import (
	"fmt"
	"testing"
)

type testAttributeList []testAttribute
type testAttribute testPartialAttribute

type testAddRequest struct {
	Entry      LDAPDN
	Attributes testAttributeList
}

type testPartialAttribute struct {
	Type   LDAPString
	Values []OctetString
}

// writeComponents on testAddRequest writes its fields into the given DERPacket.
func (req *testAddRequest) writeComponents(packet *DERPacket) (err error) {
	// Write the DN (an LDAPDN, represented as an LDAPString)
	if _, err = packet.Write(LDAPString(req.Entry)); err != nil {
		return
	}
	// Write the list of Attributes as a constructed element.
	_, err = packet.WriteConstructed(classUniversal, tagSequence, func(sub *DERPacket) (err error) {
		for _, attr := range req.Attributes {
			// Each attribute is written as a constructed element.
			if err = (*testAttribute)(&attr).write(sub); err != nil {
				break
			}
		}
		return
	})
	return
}

// write writes a single testPartialAttribute (i.e. testAttribute) into the DERPacket.
func (attr *testAttribute) write(packet *DERPacket) (err error) {
	// Write the attribute Type.
	if _, err = packet.Write(LDAPString(attr.Type)); err != nil {
		return
	}
	// Write the attribute Values as a constructed element.
	_, err = packet.WriteConstructed(classUniversal, tagOctetString, func(valPacket *DERPacket) (err error) {
		for _, value := range attr.Values {
			if _, err = valPacket.Write(value); err != nil {
				break
			}
		}
		return
	})
	return
}

func (r testAddRequest) tag() int { return 8 } // RFC4511 s. 4.7

// readComponents on testAddRequest reads its fields from the DERPacket.
func (req *testAddRequest) readComponents(packet *DERPacket) error {
	// Read the Entry from a primitive field.
	var ls LDAPString
	if err := packet.Read(&ls); err != nil {
		return fmt.Errorf("reading Entry: %w", err)
	}
	req.Entry = LDAPDN(ls)

	// Read the Attributes field as a constructed element.
	return packet.ReadConstructed(classUniversal, tagSequence, func(sub *DERPacket) error {
		for sub.HasMoreData() {
			var par testPartialAttribute
			if err := par.read(sub); err != nil {
				return fmt.Errorf("reading attribute: %w", err)
			}
			req.Attributes = append(req.Attributes, testAttribute(par))
		}
		return nil
	})
}

// read reads a testPartialAttribute from the DERPacket.
func (attr *testPartialAttribute) read(packet *DERPacket) error {
	// Read the attribute Type.
	var ls LDAPString
	if err := packet.Read(&ls); err != nil {
		return fmt.Errorf("reading attribute Type: %w", err)
	}
	attr.Type = LDAPString(ls)

	// Read the attribute Values as a constructed element.
	return packet.ReadConstructed(classUniversal, tagOctetString, func(sub *DERPacket) error {
		for sub.HasMoreData() {
			var value OctetString
			if err := sub.Read(&value); err != nil {
				return fmt.Errorf("reading attribute value: %w", err)
			}
			attr.Values = append(attr.Values, value)
		}
		return nil
	})
}

func TestASN1_codecov(t *testing.T) {
	var srcs Sources
	sizeTagAndLength(1, 10)
	sizeTagAndLength(51, 10)
	sizeTagAndLength(51, 1009)
	sizeBase128Int(768)

	_, _ = srcs.X690().DER([]byte{})
	_, _ = srcs.X690().DER([]byte{}, 1)
	_, _ = srcs.X690().DER([]byte{}, rune(1))

	var enum Enumerated
	var intg Integer
	var bl Boolean

	var der *DERPacket
	der.Read(nil)
	der = &DERPacket{data: nil}
	der.Read(nil)
	der.Read(&enum, map[Enumerated]string{})
	der.Read(&enum, nil)
	der.Read(&intg)
	der.Read(&bl)
	der.writeEnumerated(nil)
	der.writeInteger(nil)
	der.writeBoolean(nil)
	der.writeOctetString(nil)
	der.Write(nil)
	der.Data()
	der.readBase128Int()
	der.Offset()
	der.SetOffset()
	der.data = []byte{0xff, 0x2, 0x3, 0x4, 0x5}
	der.SetOffset(3)
	der.Dump()
	der.readBase128Int()
	der.WriteTagAndLength(0, true, 31, 5)
	der.WriteTagAndLength(0, true, 32, 5)
	der.WriteTagAndLength(0, true, 32, 515)
	der.WriteConstructed(2, 1, func(*DERPacket) error { return errorTxt("msg") })
	der.ReadConstructed(2, 1, func(*DERPacket) error { return errorTxt("msg") })
	der.TagAndLength()
	der.writeEnumerated(1)
	der.writeEnumerated(int32(1))
	der.writeBoolean(true)
	der.WriteTagAndLength(1, true, 2, 5)
	der.Read(&intg)
	der.ReadConstructed(0, 1, func(*DERPacket) error { return errorTxt("msg") })

	sizePrimitiveSubBytes(2, intg)
	sizePrimitiveSubBytes(2, nil)
	encodeBase128Int(1)
	encodeBase128Int(10)
	encodeBase128Int(100)
	encodeBase128Int(138500)

	der, _ = srcs.X690().DER()
	der.Free()
	der.Write(intg)
	der.WriteTagAndLength(1, false, 2, 0)
	der.Write(intg)
	der.WriteTagAndLength(0, false, 2, 1)

	bewl := true
	bl = Boolean{&bewl}
	intg = Integer(*newBigInt(0))
	der.Write(enum)
	der.Write(bl)
	der.Read(&bl)

	der.Read(&intg)
	der.Read(struct{}{})
	der.Read(&enum)
	der.Read(&enum, nil)
	der.Read(&enum, map[Enumerated]string{})

	der3, _ := srcs.X690().DER()
	der3.Read(struct{}{})
	t.Logf("DATA: %#v\n", der)
	der3.offset = 15
	der3.data = append(der.data, []byte{0x1, 0x1, 0x0, 0xfe}...)
	der3.ReadConstructed(3, 1, func(*DERPacket) error { return errorTxt("error") })

	der3, _ = srcs.X690().DER()
	der3.WriteTagAndLength(0, false, 18, 0)
	der3.Read(testAddRequest{})
	der3.offset = 15
	der3.ReadConstructed(3, 1, func(*DERPacket) error { return nil })
	der3.data = append(der.data, []byte{0x1, 0x1, 0xfe}...)
	der3.ReadConstructed(3, 1, func(*DERPacket) error { return nil })
	der3.TagAndLength()
	der3.Read(nil)

	der3, _ = srcs.X690().DER()
	for i := 0; i < 200; i++ {
		der3.data = append(der.data, []byte{0x1}...)
	}
	_, err := der3.TagAndLength()
	t.Logf("ERR: %v\n", err)

	der2, _ := srcs.X690().DER()
	der2.data = der.data
	der2.WriteTagAndLength(1, false, 2, 1)
	der2.Read(nil)
	der2.ReadConstructed(0, 2, func(*DERPacket) error { return errorTxt("error") })

	tal, _ := der.TagAndLength()
	//der.readInteger(&intg,tal)
	//der.readBoolean(&bl,tal)
	tal.Expect(2, 90, true)
	tal.ExpectClass(2)
	tal.ExpectTag(90)
	tal.ExpectCompound(true)
	tal.Equal(TagAndLength{2, 90, false, 0})
	tal.Equal(TagAndLength{2, 90, false, 0}, true)

	var death *DERPacket = &DERPacket{}
	death.Free()

	// error raisers
	_ = errorASN1Expect(1, 2, "Tag")
	_ = errorASN1Expect(0, 1, "Class")
	_ = errorASN1Expect(false, true, "Compound")
	_ = errorASN1ConstructedTagClass(
		TagAndLength{
			Tag: 1,
		},
		TagAndLength{
			Tag: 2,
		})
}

func TestReadConstructed_TagMismatch(t *testing.T) {
	// Identifier 0x45:
	//   - Class: (0x45 >> 6) = 0x1 (Application)
	//   - Constructed flag: 0x45 & 0x20 = 0 (non-constructed)
	//   - Tag: 0x45 & 0x1F = 5
	// Expected for this test is Application (class 1), tag 5, constructed.
	// We also provide a short-form length (0x00) so there is no content.
	data := []byte{0x45, 0x00}
	der := &DERPacket{
		data:   data,
		offset: 0,
	}

	// When calling ReadConstructed with expectedClass=Application, expectedTag=5,
	// the header from our DERPacket does not match (because IsCompound is false).
	err := der.ReadConstructed(classApplication, 5, func(sub *DERPacket) error {
		return nil
	})
	if err == nil {
		t.Error("Expected error due to tag mismatch (non-constructed flag) but got nil")
		return
	}
}

func TestTagAndLength_LongFormTagError(t *testing.T) {
	// Test condition (1): Force error in long-form tag parsing.
	// Construct a DERPacket where the identifier byte signals a long-form tag (0x1f)
	// but no subsequent bytes exist.
	// For example, using a single byte: 0x1F
	data := []byte{0x1F}
	der := &DERPacket{
		data:   data,
		offset: 0,
	}
	_, err := der.TagAndLength()
	if err == nil {
		t.Error("expected error for long-form tag parsing due to missing subsequent bytes, got nil")
	}
}

func TestTagAndLength_IndefiniteLengthNotPermitted(t *testing.T) {
	// Test condition (2): Create a DERPacket where the length byte
	// is in long form but encodes an indefinite length.
	// For example, for a primitive type (say, OCTET STRING with tag 0x04),
	// use the following bytes:
	//   Tag byte: 0x04 (Universal, primitive, tag=4)
	//   Length byte: 0x80 means long-form with 0 subsequent length bytes.
	data := []byte{0x04, 0x80}
	der := &DERPacket{
		data:   data,
		offset: 0,
	}
	_, err := der.TagAndLength()
	if err == nil {
		t.Error("expected error for indefinite length (numBytes==0), got nil")
	}
}

func TestTagAndLength_TruncatedLength(t *testing.T) {
	// Test condition (3): Build a DERPacket that indicates a long-form length with,
	// for example, 2 bytes of length data, but supply only one byte.
	// For instance, for an integer (tag 0x02):
	//   Tag byte: 0x02
	//   Length byte: 0x82 means two subsequent bytes for length.
	//   Then supply only one byte for length (e.g., 0x10).
	data := []byte{0x02, 0x82, 0x10} // Missing one more length byte.
	der := &DERPacket{
		data:   data,
		offset: 0,
	}
	_, err := der.TagAndLength()
	if err == nil {
		t.Error("expected error for truncated length (insufficient bytes for length field), got nil")
	}
}

func TestReadConstructed_DataTruncated(t *testing.T) {
	// Identifier 0x65:
	//   - (0x65 >> 6) = 0x1 (Application)
	//   - 0x65 & 0x20 = 0x20 (constructed)
	//   - Tag: 0x65 & 0x1F = 5
	// Then, we supply a length of 10 (0x0A) in short form.
	// However, we will not include any content bytes.
	data := []byte{0x65, 0x0A}
	der := &DERPacket{
		data:   data,
		offset: 0,
	}

	// This should trigger the truncated data condition.
	err := der.ReadConstructed(classApplication, 5, func(sub *DERPacket) error {
		return nil
	})
	if err == nil {
		t.Error("Expected error due to data truncated but got nil")
		return
	}
}

func TestDERPacket_InvalidClass(t *testing.T) {
	var oct OctetString = OctetString(`testing`)

	// Build a DER encoding for an OCTET STRING.
	// 0x04 -> tag for OCTET STRING (primitive, Universal)
	// 0x81 -> indicates long-form length with 1 subsequent byte.
	// 0xC8 -> 200 in hexadecimal.
	header := []byte{0x44, 0x03, 0x61, 0x62, 0x63}
	der := &DERPacket{
		data:   header,
		offset: 0,
	}

	t.Logf("%v\n", der.Read(&oct))
}

func TestDERPacket_LongFormLength(t *testing.T) {
	// Create 200 content bytes.
	content := make([]byte, 200)
	for i := range content {
		content[i] = 0xAA
	}

	// Build a DER encoding for an OCTET STRING.
	// 0x04 -> tag for OCTET STRING (primitive, Universal)
	// 0x81 -> indicates long-form length with 1 subsequent byte.
	// 0xC8 -> 200 in hexadecimal.
	header := []byte{0x04, 0x81, 0xC8}
	derBytes := append(header, content...)

	// Initialize the DERPacket with the constructed bytes.
	der := &DERPacket{
		data:   derBytes,
		offset: 0,
	}

	// Call TagAndLength, which should now use the long-form branch.
	tal, err := der.TagAndLength()
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	if tal.Length != 200 {
		t.Errorf("%s failed:\n\twant: 200\n\tgot:  %d", t.Name(), tal.Length)
		return
	}
}

func TestDERPacket_testAddRequest(t *testing.T) {
	// Create a fake AddRequest.
	req := testAddRequest{
		Entry: LDAPDN("cn=John Doe,dc=example,dc=com"),
		Attributes: testAttributeList{
			testAttribute{
				Type:   LDAPString("mail"),
				Values: []OctetString{[]byte("john.doe@example.com")},
			},
			testAttribute{
				Type:   LDAPString("telephoneNumber"),
				Values: []OctetString{[]byte("555-1234"), []byte("555-5678")},
			},
		},
	}

	srcs := Sources{}
	der, err := srcs.X690().DER()
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// Write the testAddRequest into the DERPacket as a constructed element.
	// Here, we use an application-specific tag for the overall AddRequest (tag 8)
	if _, err = der.WriteConstructed(classApplication, req.tag(), func(sub *DERPacket) error {
		return req.writeComponents(sub)
	}); err != nil {
		t.Errorf("%s failed [WriteConstructed]: %v", t.Name(), err)
		return
	}

	// Reset the offset so we can read from the beginning.
	der.SetOffset()

	// Now read the DERPacket back into a new testAddRequest.
	var req2 testAddRequest
	if err = der.ReadConstructed(classApplication, req.tag(), func(sub *DERPacket) error {
		return req2.readComponents(sub)
	}); err != nil {
		t.Errorf("%s failed [ReadConstructed]: %v", t.Name(), err)
		return
	}

	// verify consistency between phases
	if string(req.Entry) != string(req2.Entry) {
		t.Errorf("%s failed [DN]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), req.Entry, req2.Entry)
		return
	}

	for idx, at := range req.Attributes {
		for idx2, val := range at.Values {
			if val2 := req2.Attributes[idx].Values[idx2]; string(val2) != string(val) {
				t.Errorf("%s failed [Attributes]:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), val2, val)
				return
			}
		}
	}
}

//func TestDERPacket_ReadConstructed(t *testing.T) {
//	if err := d.ReadSubBytes(classApplication, TagAddRequest, req.readComponents); err != nil {
//}

func TestX690_DER(t *testing.T) {
	var b Boolean
	b.Set(true)

	var err error

	if _, err = srcs.X690().DER(b); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// Next, we'll do integers. Start with the special
	// integer type, which simply wraps *big.Int.
	var i Integer
	if i, err = srcs.RFC4517().Integer(378249); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// Process Integer
	if _, err = srcs.X690().DER(i); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// Try an int32 instead of Integer.
	if _, err = srcs.X690().DER(int32(453)); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	// Try OctetString
	var o OctetString
	if o, err = srcs.RFC4517().OctetString([]byte(`fhfsjk3w829879fssi_)_)983`)); err != nil {
		t.Errorf("%s failed [RFC4517.OctetString]: %v", t.Name(), err)
		return
	}
	//t.Logf("%#v\n", o) // contains the expected content

	//var ob *DERPacket
	if _, err = srcs.X690().DER(o); err != nil {
		t.Errorf("%s failed [X690.DER(OCTETSTRING)]: %v", t.Name(), err)
		return
	}
	//t.Logf("%#v\n", ob) // is empty
}

func ExampleDERPacket_read() {
	var der *DERPacket
	var srcs Sources
	var err error

	if der, err = srcs.X690().DER("applicationProcess"); err != nil {
		fmt.Println(err)
		return
	}

	var ls LDAPString
	if err = der.Read(&ls); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ls)
	// Output: applicationProcess
}

func ExampleDERPacket_readWrite() {
	var der *DERPacket
	var srcs Sources
	var err error

	if der, err = srcs.X690().DER("applicationProcess"); err != nil {
		fmt.Println(err)
		return
	}

	// Read DERPacket into OctetString
	var oct OctetString
	if err = der.Read(&oct); err != nil {
		fmt.Println(err)
		return
	}

	// Make a new DERPacket into which we
	// will write our OctetString. This is
	// merely to prove the exchange worked.
	der2, _ := srcs.X690().DER() // initialize empty packet
	if _, err = der2.Write(oct); err != nil {
		fmt.Println(err)
		return
	}
	// DERPacket "%#x": 0x04126170706c69636174696f6e50726f63657373

	// Read new DERPacket into new OctetString
	var oct2 OctetString
	if err = der2.Read(&oct2); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(oct2)
	// Output: applicationProcess
}

func ExampleEnumerated() {
	var names map[Enumerated]string = map[Enumerated]string{
		Enumerated(0): "baseObject",
		Enumerated(1): "singleLevel",
		Enumerated(2): "wholeSubtree",
	}

	var srcs Sources
	e, err := srcs.X680().Enumerated(0, names)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(names[e])
	// Output: baseObject
}
