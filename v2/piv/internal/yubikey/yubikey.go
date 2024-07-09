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

import (
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv/internal/generic"
	"github.com/go-piv/piv-go/v2/piv/protocol"
)

func init() {
	protocol.RegisterImpl(protocol.YubiKey, NewSmartCard)
}

var (
	// yubikey vendor specific extensions TODO(joelferrier): move to dedicated package
	// https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-admin-data
	// https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#getdatatable
	TagAdminData   = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x00)
	TagAttestation = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x01)
	TagMSCMap      = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x10)
	TagMSRoots1    = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x11)
	TagMSRoots2    = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x12)
	TagMSRoots3    = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x13)
	TagMSRoots4    = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x14)
	TagMSRoots5    = protocol.NewDataTag(protocol.ConstraintUnauthenticated, protocol.ConstraintManagementKey, 0x5F, 0xFF, 0x15)
)

// yubikey extensions
/*
GetSerial()
GetVersion()
Attest()
Reset()
SetManagementKey()
GetMetadata() / SetMetadata()?
*/

func NewSmartCard(reader string) (protocol.SmartCard, error) {
	sc, err := generic.NewSmartCard(reader)
	if err != nil {
		return nil, err
	}
	generic, ok := sc.(*generic.SmartCard)
	if !ok {
		return nil, fmt.Errorf("TODO(joelferrier): better error type here")
	}
	yk := &YubiKey{SmartCard: generic}

	return yk, nil
}

type YubiKey struct {
	*generic.SmartCard
	// TODO(joelferrier): embed generic implementation

	// Cached responses
	vers protocol.Version
}

// generic methods which don't necessarily need to be reimplemented
// func (yk *YubiKey) Certificate() {
//
// }
//
// func (yk *YubiKey) PrivateKey() {
//
// }
//
// func (yk *YubiKey) Retries() {
//
// }
//
// func (yk *YubiKey) SetCertificate() {
//
// }
//
// func (yk *YubiKey) SetManagementKey() {
//
// }
//
// func (yk *YubiKey) SetPIN() {
//
// }
// func (yk *YubiKey) SetPUK() {
//
// }
// func (yk *YubiKey) SetPrivateKeyInsecure() {
//
// }
// func (yk *YubiKey) Unblock() {
//
// }
// func (yk *YubiKey) VerifyPIN() {
//
// }

// yubikey extensions
func (sc *YubiKey) Attest() (*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc *YubiKey) AttestationCertificate() (*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc *YubiKey) Reset() error {
	return fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc *YubiKey) Serial() (uint32, error) {
	return 0, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (yk *YubiKey) Version() (protocol.Version, error) {
	if yk.vers != (protocol.Version{}) {
		return yk.vers, nil
	}

	resp, err := yk.SmartCard.Transmit(SelectPIVApplication, GetVersion)
	if err != nil {
		return protocol.Version{}, fmt.Errorf("command failed: %v", err)
	}
	if len(resp) != 2 {
		return protocol.Version{}, fmt.Errorf("expected 2 responses, got: %d", len(resp))
	}
	if len(resp[1].Data) != 3 {
		return protocol.Version{}, fmt.Errorf("expected response to have 3 bytes, got: %d", len(resp[0].Data))
	}
	// Cache firmware version.
	yk.vers = protocol.Version{
		Major: int(resp[1].Data[0]),
		Minor: int(resp[1].Data[1]),
		Patch: int(resp[1].Data[2]),
	}
	return yk.vers, nil
}

// func (yk *YubiKey) Metadata() { // TODO(joelferrier): leave out of API interface for now
//
// }
// func (yk *YubiKey) SetMetadata() { // TODO(joelferrier): leave out for now...
//
// }
