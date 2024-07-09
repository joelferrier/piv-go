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

package yubikey

import "github.com/go-piv/piv-go/v2/piv/protocol"

const (
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
	InsSetMGMKey     protocol.Instruction = 0xFF
	InsImportKey     protocol.Instruction = 0xFE
	InsGetVersion    protocol.Instruction = 0xFD
	InsReset         protocol.Instruction = 0xFB
	InsSetPINRetries protocol.Instruction = 0xFA
	InsAttest        protocol.Instruction = 0xF9
	InsGetSerial     protocol.Instruction = 0xF8
	InsGetMetadata   protocol.Instruction = 0xF7 // TODO(joelferrier): check if standard
	InsReadConfig    protocol.Instruction = 0x1d // TODO(joelferrier): check if standard
	InsDeviceReset   protocol.Instruction = 0x1f // TODO(joelferrier): check if standard
)

// TODO(joelferrier): export
var (
	// TODO(joelferrier): check if any of these application IDs are standardized (maybe PIV application ID is...)
	// aid == ApplicationID -> rename to {Foo}ApplicationID
	aidPIV        = [...]byte{0xa0, 0x00, 0x00, 0x03, 0x08}
	aidManagement = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}
	aidYubiKey    = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01}
)

var (
	SelectPIVApplication = protocol.NewCommand(
		protocol.StandardCommand,
		protocol.InsSelectApplication, protocol.ParamUNKNOWN3, protocol.EmptyParam,
		aidPIV[:],
	)
	SelectManagementApplication = protocol.NewCommand(
		protocol.StandardCommand,
		protocol.InsSelectApplication, protocol.ParamUNKNOWN3, protocol.EmptyParam,
		aidManagement[:],
	)
	SelectYubiKeyApplication = protocol.NewCommand(
		protocol.StandardCommand,
		protocol.InsSelectApplication, protocol.ParamUNKNOWN3, protocol.EmptyParam,
		aidYubiKey[:],
	)
	GetVersion = protocol.NewCommand(
		protocol.StandardCommand,
		InsGetVersion, protocol.EmptyParam, protocol.EmptyParam,
		nil,
	)
)
