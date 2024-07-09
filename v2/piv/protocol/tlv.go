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

package protocol

import "fmt"

type Tag []byte

var (
	// TODO(joelferrier): link to NIST reference for tags
	// TODO(joelferrier): deconflict with DataTag objects
	TagObjectData Tag = []byte{0x53}
	TagObjectID   Tag = []byte{0x5C}
)

// TODO(joelferrier): bounds check on value length
// TODO(joelferrier): typ param -> Tag (instead of []byte)
func NewTLV(typ []byte, val []byte) (TypeLengthValue, error) {
	return TypeLengthValue{typ: typ, val: val}, nil
}

// size == type size
// TODO(joelferrier): bounds check on value length
func ParseTLV(size int, data []byte) (TypeLengthValue, []byte, error) {
	if size <= 0 {
		// TODO(joelferrier): return error
		return TypeLengthValue{}, nil, fmt.Errorf("tlv type size too small") // TODO(joelferrier): better error
	}
	if len(data) < size+1 { // expect size bytes (type) + 1 byte indicating data length (may be 0x00)
		return TypeLengthValue{}, nil, fmt.Errorf("tlv data too small") // TODO(joelferrier): better error
	}
	typ := data[:size] // TODO(joelferrier): make a copy of slice?
	length := uint(data[size])
	// check data length
	if len(data) < size+1+int(length) {
		return TypeLengthValue{}, nil, fmt.Errorf("tlv data too small") // TODO(joelferrier): better error
	}
	parsed := data[size+1 : length] // TODO(joelferrier): make a copy of data?

	return TypeLengthValue{typ: typ, val: parsed}, data[length:], nil
}

type TypeLengthValue struct {
	typ, val []byte
}

func (tlv TypeLengthValue) Type() []byte {
	return tlv.typ
}

func (tlv TypeLengthValue) Value() []byte {
	return tlv.val
}

func (tlv TypeLengthValue) Encode() []byte {
	// TODO(joelferrier): bounds check
	out := make([]byte, len(tlv.typ)+len(tlv.val)+1) // Additional byte used to encode value length.
	copy(out[:len(tlv.typ)], tlv.typ)
	out[len(tlv.typ)] = byte(len(tlv.val))
	copy(out[len(tlv.typ)+1:], tlv.val)
	return out
}
