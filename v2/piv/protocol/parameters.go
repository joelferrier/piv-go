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

type Parameter byte

// TODO(joelferrier): constant parameters here

const (
	// TODO(joelferrier): document (used in GetData)
	ParamUNKNOWN1 Parameter = 0x3f
	ParamUNKNOWN2 Parameter = 0xff
	// TODO(joelferrier): document (used in select application)
	ParamUNKNOWN3 Parameter = 0x04

	EmptyParam Parameter = 0x00
	// TODO(joelferrier): document if these are standard or not...
	// paramPINAuth = 0x80
	// paramOCCAuth = 0x96 // TODO(joelferrier): start using this here
)

// param1:      0x3f, // TODO(joelferrier): document
// param2:      0xff, // TODO(joelferrier): document
