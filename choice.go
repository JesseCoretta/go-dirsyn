package dirsyn

import (
	"encoding/asn1"
	"errors"
	"strconv"
)

/*
Choice implements an interface-based ASN.1 CHOICE type.
*/
type Choice interface {
	// AcceptsTag returns true if the alternative can decode an ASN.1
	// value with the given tag.  This is used for particular Choice
	// qualifiers which are known to be encoded using one of multiple
	// possible ASN.1 tags.
	AcceptsTag(int) bool

	// DecodeChoice decodes the ASN.1 data from the provided RawValue
	// into the concrete Choice type implementing the interface.
	DecodeChoice(asn1.RawValue) error
}

/*
Choices implements a [Choice] registry. Instances of this type are used as
the platform upon which a specific ASN.1 CHOICE may be chosen based on an
input ASN.1 DER byte value.

See also [Choices.Register], [Choices.Len] and [Choices.Unmarshal].
*/
type Choices []Choice

/*
Register registers a [Choice] in the receiver registry instance.
*/
func (r *Choices) Register(choice Choice) {
	(*r) = append((*r), choice)
}

/*
Len returns the integer length of the receiver instance.
*/
func (r Choices) Len() int { return len(r) }

/*
Unmarshal returns an instance of [Choice] alongside an error following an
attempt to unmarshal data as an ASN.1 CHOICE.

The receiver instance contains all possible [Choice] qualifiers, which are
used to select an appropriate tag-matched instance.
*/
func (r Choices) Unmarshal(data []byte) (choice Choice, err error) {
	var (
		raw  asn1.RawValue
		rest []byte
	)

	if rest, err = asn1.Unmarshal(data, &raw); err != nil {
		return
	} else if len(rest) > 0 {
		err = errors.New("unexpected extra data after ASN.1 object")
		return
	}

	for i := 0; i < r.Len() && choice == nil && err == nil; i++ {
		if alt := r[i]; alt.AcceptsTag(raw.Tag) {
			if err = alt.DecodeChoice(raw); err == nil {
				choice = alt
			}
		}
	}

	err = errEmptyChoice(choice, raw.Tag)

	return
}

func errEmptyChoice(choice Choice, tag int) (err error) {
	if choice == nil {
		err = errors.New("No matching CHOICE alternative found for tag " + strconv.Itoa(tag))
	}

	return
}
