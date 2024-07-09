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

type EncodingType int

const (
	// ISO/IEC 7816-4
	SimpleEncodingType EncodingType = iota + 1
	// ISO/IEC 7816-4
	BEREncodingType
	// US specific X.690 -> copied to ISO/IEC 7816-4
	// but without indefinate form
)

func (e EncodingType) String() string {
	switch e {
	case SimpleEncodingType:
		return "SimpleEncoding"
	case BEREncodingType:
		return "BEREncoding"
	default:
		return fmt.Sprintf("UnknownEncoding(%d)", e)
	}
}

var (
	SimpleEncoding = EncoderOptions{
		Type: SimpleEncodingType,
	}
	BEREncoding = EncoderOptions{
		Type: BEREncodingType,
	}
)

type EncoderOptions struct {
	Type EncodingType
	// TODO(joelferrier): indefinate bool
}

const maxSimpleTLVLength = 0xFFFF

func (e EncoderOptions) Encode(tag Tag, value []byte) (TLV, error) {
	switch e.Type {
	case SimpleEncodingType:
		st, err := tag.Simple()
		if err != nil {
			return nil, err
		}
		if len(value) > maxSimpleTLVLength {
			return nil, fmt.Errorf("tlv SimpleEncoding requires value length <= %d got value length %d", maxSimpleTLVLength, len(value))
		}
		return &simple{tag: st, val: value}, nil
	case BEREncodingType:
		// TODO(joelferrier): implement
		return nil, fmt.Errorf("tlv %v unimplemented", e)
	}
	return nil, fmt.Errorf("tlv %v", e)
}

type TLV interface {
	Tag() Tag
	Value() []byte
	// TODO(joelferrier): add Type() which returns BER type or generic value for simple
	Size() uint
	Encoding() EncodingType
	Encode() []byte
}

type simple struct {
	tag byte
	val []byte
}

func (s *simple) Tag() Tag {
	return NewSimpleTag(s.tag)
}

func (s *simple) Value() []byte {
	ret := make([]byte, len(s.val))
	copy(ret, s.val)
	return ret
}

func (s *simple) Size() uint {
	if len(s.val) < 0xFF {
		return uint(1 + 1 + len(s.val)) // 1 tag byte, 1 length byte, variable value bytes
	}
	// 1 tag byte, 3 length bytes (1 static, 2 for length value), variable value bytes
	return uint(1 + 3 + len(s.val))
}

// TODO(joelferrier): remove
func (s *simple) Encoding() EncodingType {
	return SimpleEncodingType
}

func (s *simple) Encode() []byte {
	out := make([]byte, s.Size())
	out[0] = s.tag
	if len(s.val) < 0xFF {
		out[1] = byte(len(s.val))
		copy(out[1:], s.val)
	} else {
		out[1] = 0xFF
		binary.BigEndian.PutUint16(out[2:4], uint16(len(s.val)))
		copy(out[4:], s.val)
	}
	return out
}

type ber struct {
	tag byte
	// TODO(joelferrier): typ (of value)
	val []byte
}

func (b *ber) Tag() []byte {
	return nil
}

func (b *ber) Value() []byte {
	return nil
}

func (b *ber) Size() uint {
	return 0
}

func (b *ber) Encoding() EncodingType {
	return BEREncodingType
}

/*
The tag field T consists of one or more consecutive bytes.
It encodes a class, a type and a number.
The length field consists of one or more consecutive bytes. It encodes an integer L.
If L is not null, then the value field V consists of L consecutive bytes.
If L is null, then the data object is empty: there is no value field.
*/
func (b *ber) Encode() []byte {
	return nil
}

func Decode(data []byte) (TLV, error) {
	if len(data) == 0 {
		// TODO(joelferrier): return error
	}

	if data[0] == 0x00 || data[0] == 0xFF {
		return nil, fmt.Errorf("simple TLV encoding reserves tag values 0x00 and 0xFF got 0x%X bytes", data[0]) // TODO(joelferrier): cleanup error
	}

	// TODO(joelferrier): decode tag

	// TODO(joelferrier): return error if remaining bytes after parsing TLV
	return nil, nil
}

// TODO(joelferrier): rename
func DecodeMany(data []byte) ([]TLV, error) {
	return nil, nil
}
