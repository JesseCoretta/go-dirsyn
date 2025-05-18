package dirsyn

/*
asn1.go handles ITU-T X.690 DER encoding for various types.
*/

import (
	"math/big"
)

// ASN.1 tag constants
const (
	tagBoolean         = 1
	tagInteger         = 2
	tagBitString       = 3
	tagOctetString     = 4
	tagOID             = 6
	tagEnum            = 10
	tagUTF8String      = 12
	tagSequence        = 16
	tagSet             = 17
	tagPrintableString = 19
	tagT61String       = 20
	tagIA5String       = 22
	tagUTCTime         = 23
	tagGeneralizedTime = 24
	tagGeneralString   = 27
)

// ASN.1 class constants
const (
	classUniversal       = 0
	classApplication     = 1
	classContextSpecific = 2
	//classPrivate         = 3 // not implemented
)

var ClassNames = map[int]string{
	classUniversal:       "UNIVERSAL",
	classApplication:     "APPLICATION",
	classContextSpecific: "CONTEXT SPECIFIC",
	//classPrivate:         "PRIVATE", // not implemented
}

var TagNames = map[int]string{
	tagBoolean:     "BOOLEAN",
	tagInteger:     "INTEGER",
	tagOctetString: "OCTET STRING",
	tagEnum:        "ENUM",
	tagSequence:    "SEQUENCE",
	tagSet:         "SET",
}

var CompoundNames = map[bool]string{
	true:  "COMPOUND",
	false: "NOT COMPOUND",
}

// TagAndLength represents a parsed DER tag/length header.
type TagAndLength struct {
	Class      int
	Tag        int
	IsCompound bool
	Length     int
}

/*
DERPacket encapsulates an [ITU-T Rec. X.690] DER-encoded byte slice and an offset.

[ITU-T Rec. X.690]: https://www.itu.int/rec/T-REC-X.690
*/
type DERPacket struct {
	data   []byte
	offset int
}

/*
DER returns an instance of *[DERPacket] alongside an error.
*/
func (r X690) DER(x ...any) (*DERPacket, error) {
	var (
		der *DERPacket
		err error
	)

	if len(x) > 0 {
		switch tv := x[0].(type) {
		case []byte:
			if len(x) > 1 {
				if i, ok := x[1].(int); ok {
					der = newDERPacket([]byte{}, i)
				} else {
					der = newDERPacket([]byte{})
				}
			} else {
				der = newDERPacket([]byte{})
				_, err = der.Write(tv)
			}
		default:
			der = newDERPacket([]byte{})
			_, err = der.Write(tv)
		}
	} else {
		der = newDERPacket([]byte{})
	}

	return der, err
}

/*
newDERPacket returns an empty *[DERPacket] for read or write operations.

If the variadic size var is included, this preallocates N bytes and discards data.
*/
func newDERPacket(data []byte, size ...int) *DERPacket {
	var der *DERPacket

	if len(size) > 0 {
		der = &DERPacket{data: make([]byte, size[0]), offset: 0}
	} else {
		der = &DERPacket{data: data, offset: 0}
	}

	return der
}

/*
HasMoreData returns a Boolean value indicative of whether there
are more bytes to process.
*/
func (r DERPacket) HasMoreData() bool {
	return r.offset < len(r.data)
}

/*
Data returns the underlying byte slice.
*/
func (r DERPacket) Data() []byte {
	return r.data
}

/*
Offset returns the current offset position index of the underlying value
within the receiver instance.
*/
func (r DERPacket) Offset() int { return r.offset }

/*
SetOffset replaces the current offset position index of the underlying
value within the receiver instance with a user-supplied value.

This method is intended for use in special cases where a particular
packet may need to be re-read for some reason.

If no variadic input is provided, the offset position index is set to
zero (0).
*/
func (r *DERPacket) SetOffset(offset ...int) {
	var off int
	if len(offset) > 0 {
		if 0 <= offset[0] && offset[0] < len(r.data) {
			off = offset[0]
		}
	}
	r.offset = off
}

/*
Dump returns a quick hexadecimal dump of the current byte and its neighbors.
Use of this method is mainly intended for debugging.
*/
func (r DERPacket) Dump() string {
	var parts [3]string
	for i := -1; i <= 1; i++ {
		idx := r.offset + i
		if idx >= 0 && idx < len(r.data) {
			// Manually format the byte value as hexadecimal with a "0x" prefix.
			parts[i+1] = "0x" + fmtUint(uint64(r.data[idx]), 16)
		}
	}
	// Manually assemble the final string: (prev), [current], (next).
	return parts[0] + ", [" + parts[1] + "], " + parts[2]
}

/*
Free frees the receiver instance.
*/
func (r *DERPacket) Free() { *r = DERPacket{} }

/*
TagAndLength returns an instance of [TagAndLength] alongside an error
following an attempt to read the next DER tag/length header.
*/
func (r *DERPacket) TagAndLength() (TagAndLength, error) {
	if r.offset >= len(r.data) {
		return TagAndLength{}, errorTxt("no data available at offset " + itoa(r.offset))
	}

	// Read the identifier byte.
	b := r.data[r.offset]
	r.offset++
	tal := TagAndLength{
		Class:      int(b >> 6),
		IsCompound: b&0x20 == 0x20,
		Tag:        int(b & 0x1f),
	}

	// If the tag field is 0x1f, we have a long-form tag.
	if tal.Tag == 0x1f {
		longTag, err := r.readBase128Int()
		if err != nil {
			return tal, err
		}
		tal.Tag = longTag
	}

	// Now, read length byte.
	if r.offset >= len(r.data) {
		return tal, errorTxt("unexpected end of data after tag")
	}
	b = r.data[r.offset]
	r.offset++

	if b&0x80 == 0 {
		// Short form: lower 7 bits is the length.
		tal.Length = int(b & 0x7f)
	} else {
		// Long form: lower 7 bits indicate the number of subsequent bytes.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			return tal, errorTxt("indefinite lengths are not permitted in DER")
		}
		length := 0
		for i := 0; i < numBytes; i++ {
			if r.offset >= len(r.data) {
				return tal, errorTxt("truncated length at offset " + itoa(r.offset))
			}
			length = (length << 8) | int(r.data[r.offset])
			r.offset++
		}
		tal.Length = length
	}

	return tal, nil
}

// readBase128Int decodes a base-128 encoded integer (used for tags >= 31).
func (r *DERPacket) readBase128Int() (int, error) {
	result := 0
	for {
		if r.offset >= len(r.data) {
			return 0, errorTxt("truncated base-128 integer")
		}
		b := r.data[r.offset]
		r.offset++
		result = (result << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	return result, nil
}

/*
WriteTagAndLength returns an int following an attempt to write a DER tag/length
header to the receiver buffer.
*/
func (r *DERPacket) WriteTagAndLength(class int, isCompound bool, tag, length int) int {
	header := []byte{}

	// Encode the identifier octet.
	b := uint8(class << 6)
	if isCompound {
		b |= 0x20
	}
	if tag < 31 {
		b |= uint8(tag)
		header = append(header, b)
	} else {
		b |= 0x1f
		header = append(header, b)
		header = append(header, encodeBase128Int(tag)...)
	}

	// Encode the length octets.
	if length < 128 {
		header = append(header, uint8(length))
	} else {
		// Build minimal length encoding.
		var lenBytes []byte
		l := length
		for l > 0 {
			// Prepend the byte.
			lenBytes = append([]byte{uint8(l & 0xff)}, lenBytes...)
			l >>= 8
		}
		header = append(header, uint8(0x80|len(lenBytes)))
		header = append(header, lenBytes...)
	}

	// Append the header to the packet's data slice.
	r.data = append(r.data, header...)
	r.offset = len(r.data)
	return len(header)
}

/*
Write returns an int alongside an error following an attempt to write
val into the receiver instance.

val may be int, int32, int64, *[big.Int], [Integer], bool, [Boolean]
or [OctetString].

b indicates the number of bytes written.
*/
func (r *DERPacket) Write(val any) (b int, err error) {
	switch val.(type) {
	case bool, Boolean:
		b, err = r.writeBoolean(val)
	case int, int32, int64, *big.Int, Integer:
		// integer wise, we support what asn1.Marshal
		// supports, plus dirsyn.Integer.
		b, err = r.writeInteger(val)
	case Enumerated:
		b, err = r.writeEnumerated(val)
	case OctetString, string, []byte:
		b, err = r.writeOctetString(val)
	case LDAPString:
		b, err = r.writeOctetString(OctetString(val.(LDAPString)))
	default:
		err = errorBadType("DER write")
	}

	if err == nil {
		r.offset = 0
	}

	return
}

func (r *DERPacket) writeEnumerated(val any) (b int, err error) {
	switch tv := val.(type) {
	case Enumerated:
		b, err = derWriteEnumerated(r, tv)
	case int:
		b, err = r.writeEnumerated(Enumerated(tv))
	case int32:
		b, err = r.writeEnumerated(Enumerated(tv))
	default:
		err = errorBadType("Enumerated")
	}

	return
}

// writeBoolean encodes a bool of [Boolean] as ASN.1 DER.
func (r *DERPacket) writeBoolean(val any) (b int, err error) {

	// DER mandates one content byte for bool.
	var content byte
	switch tv := val.(type) {
	case bool:
		x := Boolean{&tv}
		content = x.Bytes()[0]
	case Boolean:
		content = tv.Bytes()[0]
	default:
		err = errorBadType("DER Boolean")
	}

	if err == nil {
		b = derWriteBoolean(r, content)
	}

	return b, err
}

/*
writeOctetString writes a DER-encoded OctetString. It writes the ASN.1 DER header
(class universal, tag 4), the length, and finally the value itself.
*/
func (r *DERPacket) writeOctetString(x any) (n int, err error) {
	var o OctetString

	switch tv := x.(type) {
	case []byte:
		o = OctetString(tv)
	case string:
		o = OctetString([]byte(tv))
	case OctetString:
		o = tv
	default:
		err = errorBadType("DER Octet String")
	}

	if err == nil {
		n = derWriteOctetString(r, []byte(o))
	}

	return n, err
}

/*
writeInteger returns an int alongside an error following an attempt to
encode an int, int32, int64, *[big.Int] or [Integer] as ASN.1 DER within
the receiver instance.

The return int describes the number of bytes written to the receiver
instance.
*/
func (r *DERPacket) writeInteger(i any) (b int, err error) {
	var derBytes []byte

	switch tv := i.(type) {
	case int, int32, int64:
		derBytes, err = asn1m(tv)
	case Integer:
		_i := tv.Cast()             // reveals *big.Int
		b, err = r.writeInteger(_i) // re-run from top
		return
	case *big.Int:
		derBytes, err = asn1m(tv)
	default:
		err = errorBadType("DER Integer")
	}

	// Use the standard library to get a DER encoding for the INTEGER.
	if err == nil {
		b = derWriteInteger(r, derBytes)
	}

	return
}

/*
Read returns an error following an attempt to read into primitive x. x must be a pointer.

z provides variadic input. Currently, this is only used for map[Enumerated]string
instances and only when x is *[Enumerated].
*/
func (r *DERPacket) Read(x any, z ...any) (err error) {
	if r == nil {
		err = nilInstanceErr
		return
	}

	// Parse the tag/length header.
	var tal TagAndLength
	if tal, err = r.TagAndLength(); err != nil {
		return err
	} else if tal.Class != classUniversal {
		err = errorTxt("expected UNIVERSAL class")
		return
	}

	switch tv := x.(type) {
	case *OctetString:
		err = r.readOctetString(tv, tal)
	case *LDAPString:
		var o OctetString
		err = r.readOctetString(&o, tal)
		*tv = LDAPString(o)
	case *Integer:
		err = r.readInteger(tv, tal)
	case *Boolean:
		err = r.readBoolean(tv, tal)
	case *Enumerated:
		if len(z) > 0 {
			switch tv2 := z[0].(type) {
			case map[Enumerated]string:
				err = derReadEnumerated(tv, r, tal, tv2)
			default:
				err = errorBadType("Enumerated map")
			}
		} else {
			err = errorBadType("Enumerated map")
		}
	default:
		err = errorBadType("DERPacket read")
	}

	return err
}

func (r *DERPacket) readBoolean(x *Boolean, tal TagAndLength) (err error) {
	return derReadBoolean(x, r, tal)
}

func (r *DERPacket) readInteger(x *Integer, tal TagAndLength) (err error) {
	return derReadInteger(x, r, tal)
}

func (r *DERPacket) readOctetString(x *OctetString, tal TagAndLength) (err error) {
	return derReadOctetString(x, r, tal)
}

/*
ReadConstructed returns an error following an attempt to read a constructed (compound)
element from the callback-revealed *[DERPacket] into the receiver *[DERPacket].

It verifies that the element has the expected class and tag, then creates a temporary
*[DERPacket] for the sub-bytes and calls the provided callback to process them.
*/
func (r *DERPacket) ReadConstructed(expectedClass int, expectedTag int, callback func(sub *DERPacket) error) (err error) {
	// Parse the tag/length header.
	var tal TagAndLength
	if tal, err = r.TagAndLength(); err != nil {
		return
	}

	// Verify the header: check class, tag and that it is compound.
	expect := TagAndLength{
		Class:      expectedClass,
		Tag:        expectedTag,
		IsCompound: true,
	}

	if !expect.Equal(tal) {
		err = errorASN1ConstructedTagClass(expect, tal)
		return
	}

	// Save the starting offset.
	start := r.offset
	end := r.offset + tal.Length
	if end > len(r.data) {
		err = errorTxt("ReadConstructed: data truncated; expecting " + itoa(tal.Length) + " bytes at offset " + itoa(r.offset))
		return
	}

	// Create a temporary DERPacket for the sub-bytes.
	subPacket := &DERPacket{
		data:   r.data[start:end],
		offset: 0,
	}

	// Invoke the callback to process the sub-bytes.
	if err = callback(subPacket); err != nil {
		// If the callback fails, optionally update main offset (or decide to leave it unchanged).
		r.offset = end
		return
	}

	// Optionally, check that the sub-packet was fully consumed.
	if subPacket.offset != len(subPacket.data) {
		extra := len(subPacket.data) - subPacket.offset
		err = errorTxt("ReadSubBytes: data too long; " + itoa(extra) + " bytes remain unprocessed")
	} else {
		// Update the main packet's offset.
		r.offset = end
	}

	return
}

// WriteConstructed writes a constructed (compound) DER element.
// expectedClass and expectedTag define the header for the constructed element.
// The callback is used to write the sub-elements (content) into a temporary DERPacket.
func (r *DERPacket) WriteConstructed(expectedClass int, expectedTag int, callback func(sub *DERPacket) error) (n int, err error) {
	// Create a temporary DERPacket to accumulate content.
	temp := &DERPacket{
		data:   []byte{},
		offset: 0,
	}

	// Let the callback write the sub-elements into the temporary packet.
	if err = callback(temp); err != nil {
		return
	}

	// The content to be wrapped is temp.data.
	contentLength := len(temp.data)

	// Write the header to the main DERPacket.
	// This header will indicate a constructed element.
	headerSize := r.WriteTagAndLength(expectedClass, true, expectedTag, contentLength)

	// Append the content bytes.
	r.data = append(r.data, temp.data...)

	// Update the main offset.
	r.offset = len(r.data)

	// Total written bytes is header + content
	n = headerSize + contentLength
	return
}

// SizeSubBytes calculates the size of an element by taking the size returned by
// a callback (which computes the content size) and adding the DER tag/length overhead.
//func SizeSubBytes(tag int, callback func() int) int {
//	contentSize := callback()
//	headerSize := sizeTagAndLength(tag, contentSize)
//	return contentSize + headerSize
//}

func sizeTagAndLength(tag int, length int) (size int) {
	// Compute the size of the tag
	size = 1
	if tag >= 31 {
		// Long-form identifier if the tag is greater than 30
		// http://en.wikipedia.org/wiki/X.690#Identifier_tags_greater_than_30
		size += sizeBase128Int(tag)
	}
	// Compute the size of the length using the definite form
	// http://en.wikipedia.org/wiki/X.690#The_definite_form
	size += 1
	if length >= 128 {
		size += 1
		for length > 255 {
			size++
			length >>= 8
		}
	}
	return
}

func sizeBase128Int(value int) (size int) {
	for i := value; i > 0; i >>= 7 {
		size++
	}
	return
}

/*
encodeBase128Int returns the []byte encoding of an integer
as base-128 (for long-form tags).
*/
func encodeBase128Int(value int) []byte {
	var out []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		// Prepend if this isn't the last byte.
		if len(out) > 0 {
			b |= 0x80
		}
		out = append([]byte{b}, out...)
		if value == 0 {
			break
		}
	}
	return out
}

func sizePrimitiveSubBytes(tag int, value any) (size int) {
	switch tv := value.(type) {
	case Boolean:
		size = tv.Size()
	case Integer:
		size = tv.Size()
		//case ENUMERATED:
		//size = sizeInt32(int32(value.(ENUMERATED)))
	case OctetString:
		size = tv.Size()
	default:
		return
		//panic(sprintf("SizePrimitiveSubBytes: invalid value type %v", value))
	}
	size += sizeTagAndLength(tag, size)
	return
}

/*
Equal returns a Boolean value indicative of whether the receiver
instance is equal to the input [TagAndLength] instance.
*/
func (r TagAndLength) Equal(tal TagAndLength, length ...bool) bool {
	var lenOK bool = true // assume true by default
	if len(length) > 0 {
		lenOK = r.Length == tal.Length
	}

	return r.IsCompound == tal.IsCompound &&
		r.Class == tal.Class &&
		r.Tag == tal.Tag && lenOK
}

/*
Expect returns an error following a comparison of the ASN.1 class, tag and compound state
against those of the receiver instance.
*/
func (r TagAndLength) Expect(class int, tag int, IsCompound bool) (err error) {
	for _, err = range []error{
		r.ExpectClass(class),
		r.ExpectTag(tag),
		r.ExpectCompound(IsCompound),
	} {
		if err != nil {
			break
		}
	}

	return
}

/*
ExpectClass returns an error following a comparison of the ASN.1 class with the receiver's class.
*/
func (r TagAndLength) ExpectClass(class int) (err error) {
	if class != r.Class {
		err = errorASN1Expect(r.Class, class, "Class")
	}
	return
}

/*
ExpectTag returns an error following a comparison of the ASN.1 tag with the receiver's tag.
*/
func (r TagAndLength) ExpectTag(tag int) (err error) {
	if tag != r.Tag {
		err = errorASN1Expect(r.Tag, tag, "Tag")
	}
	return
}

/*
ExpectCompound returns an error following a comparison of the ASN.1 compound state with the receiver's
compound state.
*/
func (r TagAndLength) ExpectCompound(IsCompound bool) (err error) {
	if IsCompound != r.IsCompound {
		err = errorASN1Expect(r.IsCompound, IsCompound, "Compound")
	}
	return
}
