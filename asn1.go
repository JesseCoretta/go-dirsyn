package dirsyn

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
