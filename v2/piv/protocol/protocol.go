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

// Package registry ... TODO(joelferrier): doc comment
// TODO(joelferrier): rename package and move out of v2/piv/internal ? maybe to v2/piv/<something more standard>
package protocol

import (
	"crypto/x509"
	"fmt"
)

type SmartCard interface {
	// Generic low level PIV methods.
	GetData(DataTag) ([]byte, error)
	PutData(DataTag, []byte) error
	Transmit(...Command) ([]CommandResponse, error)
	Close() error
	// Generic high level PIV methods
	Certificate()
	PrivateKey()
	Retries()
	SetCertificate()
	SetPIN()
	SetPUK()
	SetPrivateKeyInsecure()
	Unblock()
	VerifyPIN()
	SetManagementKey()

	// YubiKey PIV extensions, not implemented by all PIV applets.
	Attest() (*x509.Certificate, error)
	AttestationCertificate() (*x509.Certificate, error)
	Reset() error
	Serial() (uint32, error)
	Version() (Version, error)
	// Metadata()    // SKIP THIS -> point folks to PutData instead
	// SetMetadata() // SKIP THIS -> point folks to PutData instead
}

type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
