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

package trussed

import (
	"fmt"

	"github.com/go-piv/piv-go/v2/piv/protocol"
)

func init() {
	protocol.RegisterImpl(protocol.SoloKey, NewSmartCard)
	protocol.RegisterImpl(protocol.NitroKey, NewSmartCard)
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

func NewSmartCard(reader string) (protocol.SmartCard, error) {
	return nil, fmt.Errorf("unimplemented")
}
