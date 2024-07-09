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

var (
	// TODO(joelferrier): update tag type
	CardCapabilityContainerTag = NewBERTag(ContextSpecificClass, ConstructedType, TagType(0x00))
)

// Card Capability Container
// Container: 0xDB00
// BER TLV tag: 5FC107 - 101 1111 11000001 00001011

// Card Holder Unique Identifier (CHUID)
// Container: 0x3000
// BER TLV tag: 5FC102

// X.509 Certificate for PIV Authentication (Key Reference '9A')
// Container: 0x0101
// BER TLV tag: 5FC105

// Cardholder Fingerprints
// Container: 0x6010
// BER TLV tag: 5FC103

// Security Object
// Container: 0x9000
// BER TLV tag: 5FC106

// Cardholder Facial Image
// Container: 0x6030
// BER TLV tag: 5FC108

// X.509 Certificate for Card Authentication (Key Reference '9E')
// Container: 0x0500
// BER TLV tag: 5FC101

// X.509 Certificate for Digital Signature (Key Reference '9C')
// Container: 0x0100
// BER TLV tag: 5FC10A

// X.509 Certificate for Key Management (Key Reference '9D')
// Container: 0x0102
// BER TLV tag: 5FC10B

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:

//
// Container:
// BER TLV tag:
