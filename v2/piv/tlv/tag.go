// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlv

import (
	"encoding/binary"
	"fmt"
)

type Tag []byte

func (t Tag) Simple() (byte, error) {
	if len(t) != 1 {
		// TODO(joelferrier): cleanup error messages
		return 0x00, fmt.Errorf("simple TLV encoding requires 1 byte tag, got %d bytes", len(t))
	}
	if t[0] == 0x00 || t[0] == 0xFF {
		return 0x00, fmt.Errorf("simple TLV encoding reserves tag values 0x00 and 0xFF got 0x%X bytes", t[0])
	}
	return t[0], nil
}

func (t Tag) BER(class TagClass) ([]byte, error) {
	// TODO(joelferrier): can I infer primitive vs. constructed from the tag type?
	return nil, nil
}

func NewSimpleTag(tag byte) Tag {
	return []byte{tag}
}

func NewBERTag(cls TagClass, ctyp ContentType, ttyp TagType) Tag {
	// TODO(joelferrier): implement
	return nil
}

// TODO(joelferrier): type comment indicating values are stored in high order 2 bits
type TagClass uint8

// TODO(joelferrier): match function?

const (
	// TODO(joelferrier): link to standard next to constants here
	UniversalClass       TagClass = 0x00      // 0 stored in 2 high order bits of octet.
	ApplicationClass     TagClass = 0x01 << 6 // 1 stored in 2 high order bits of octet.
	ContextSpecificClass TagClass = 0x02 << 6 // 2 stored in 2 high order bits of octet.
	PrivateClass         TagClass = 0x03 << 6 // 3 stored in 2 high order bits of octet.
)

func DecodeTagClass(octet uint8) TagClass {
	switch octet & (0x03 << 6) { // mask all but 2 high order bits
	case uint8(UniversalClass):
		return UniversalClass
	case uint8(ApplicationClass):
		return ApplicationClass
	case uint8(ContextSpecificClass):
		return ContextSpecificClass
	case uint8(PrivateClass):
		return PrivateClass
	default:
		// Functionally dead branch given the switch masking and constant values.
		return TagClass(0x00) // TODO(joelferrier): is it really okay to effectively return UniversalClass here?
	}
}

type ContentType uint8

const (
	// TODO(joelferrier): link to standard next to constants here
	PrimitiveType   ContentType = 0x00 // 0 stored in bit position 6
	ConstructedType ContentType = 0x01 // 1 stored in bit position 6
)

func DecodeContentType(octet uint8) ContentType {
	switch octet & (0x01 << 5) {
	case uint8(PrimitiveType):
		return PrimitiveType
	case uint8(ConstructedType):
		return ConstructedType
	default:
		// Functionally dead branch given the switch masking and constant values.
		return ContentType(0x00) // TODO(joelferrier): is it really okay to effectively return PrimitiveType here?
	}
}

type TagType int64 // TODO(joelferrier):

// TODO(joelferrier): add encode methods?

const (
// TODO(joelferrier): common constants from ASN.1?
)

func DecodeTagType(data []byte) (TagType, error) {
	if len(data) == 0 {
		return TagType(0), fmt.Errorf("short read") // TODO(joelferrier): better error message
		// TODO(joelferrier): return error
	}
	// Select lower 5 bits of leading byte by &-ing with b'00011111' and check if all masked
	// values are not 1s indicating the tag type is encoded the leading byte only.
	leading := data[0] & 0x1F // TODO(joelferrier): const for 0x1F (something something multi blah)
	if leading != 0x1F {      // TODO(joelferrier): const for 0x1F (something something multi blah)
		return TagType(leading), nil
	}

	if len(data) <= 1 {
		return TagType(0), fmt.Errorf("not enough bytes for long form tag") // TODO(joelferrier): better error message
		// TODO(joelferrier): error, no parseable tag :/
	}

	tag := []byte{leading}
	var done bool
	// TODO(joelferrier): range over int instead of slice
	for idx, octet := range data[1:] {
		// TODO(joelferrier): parse data
		if (octet & 0x7F) == 0x00 { // invalid tag (7 tag bits are all zeros)
			return TagType(0), fmt.Errorf("invalid long form byte index %d all zeros", idx+1) // TODO(joelferrier): better error message
		}
		// The other octets set bit 7 to 1.
		// The actual value of the tag's number is encoded as an unsigned binary integer,
		// as the concatenation of the rightmost seven bits of each octet
		// TODO(joelferrier): how are the bytes padded??
		tag = append(tag, octet&0x7F)      // mask highest order bit which is not a part of the encoded uint64
		if (octet & (0x01 << 7)) == 0x80 { // final byte has 8th bit set to b'1'
			done = true
			break
		}
		if idx > 8 { // TODO(joelferrier): revisit
			break
		}
	}
	if len(tag) > 8 {
		return TagType(0), fmt.Errorf("tag too large, bytes %d want <= 8", len(tag)) // TODO(joelferrier): better error message
	}
	// finished looping before getting final bit
	if !done {
		return TagType(0), fmt.Errorf("tag bytes consumed before end sequence encountered") // TODO(joelferrier): better error message
		// TODO(joelferrier): return error
	}

	return TagType(binary.BigEndian.Uint64(tag)), nil
	// The bits B7-B1 of the first subsequent byte, folowed by the bits B7 to B1 of each further subsequent byte, up to and including the bits B7-B1 of the last subsequent byte, shall encode an integer equal to the tag number (thus strictly positive).

	// read 7 bits of each remaining each input
	// multi-byte tag
}

/*

If the bits B5-B1 of the leading byte are not all set to 1, then may they shall encode an integer equal to the tag number which therefore lies in the range from 0 to 30. Then the tag field consists of a single byte.

Otherwise (B5-B1 set to 1 in the leading byte), the tag field shall continue on one or more subsequent bytes.

The bit B8 of each subsequent byte shall be set to 1, unless it is the last subsequent byte
The bits B7-B1 of the first subsequent byte shall not be all set to 0
The bits B7-B1 of the first subsequent byte, folowed by the bits B7 to B1 of each further subsequent byte, up to and including the bits B7-B1 of the last subsequent byte, shall encode an integer equal to the tag number (thus strictly positive).
*/

func DecodeValue(data []byte, tag Tag, encoding EncodingType) (val, remainder []byte, err error) {
	return nil, nil, nil
}
