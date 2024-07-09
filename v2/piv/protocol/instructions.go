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

// TODO(joelferrier): move to protocol package

type Instruction byte

// TODO(joelferrier): instruction constants here
// TODO(joelferrier): maybe use go generate also

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf

const (
	// TODO(joelferrier): cleanup "Ins" prefix
	InsVerify             Instruction = 0x20
	InsChangeReference    Instruction = 0x24
	InsResetRetry         Instruction = 0x2C
	InsGenerateAsymmetric Instruction = 0x47
	InsAuthenticate       Instruction = 0x87
	InsGetData            Instruction = 0xCB
	InsPutData            Instruction = 0xDB
	InsSelectApplication  Instruction = 0xA4
	InsGetResponse        Instruction = 0xC0

	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
	// insSetMGMKey     = 0xff
	// insImportKey     = 0xfe
	// insGetVersion    = 0xfd
	// insReset         = 0xfb
	// insSetPINRetries = 0xfa
	// insAttest        = 0xf9
	// insGetSerial     = 0xf8
	// insGetMetadata   = 0xf7
	// insReadConfig    = 0x1d
	// insDeviceReset   = 0x1f

	// paramPINAuth = 0x80
	// paramOCCAuth = 0x96 // TODO(joelferrier): start using this here
)
