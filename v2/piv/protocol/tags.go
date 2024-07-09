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

type DataConstraint int

func (c DataConstraint) String() string {
	switch c {
	case ConstraintUnauthenticated:
		return "Unauthenticated"
	case ConstraintManagementKey:
		return "ManagementKey"
	case ConstraintPIN:
		return "PIN"
	case ConstraintReadOnly:
		return "ReadOnly"
	default:
		return fmt.Sprintf("UnknownDataConstraint(%d)", c)
	}
}

const (
	// https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-admin-data
	// https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#getdatatable
	ConstraintUnauthenticated DataConstraint = iota + 1
	ConstraintManagementKey
	ConstraintPIN
	ConstraintReadOnly
)

const maxDataConstraint = 4

// TODO(joelferrier): get references to tags
// TODO(joelferrier): get references to tags from ISO/IEC 7816-6:2023 (TLV p1, p2 tags???)

var (
	// TODO(joelferrier): rename to Object<Foo>
	// TODO(joelferrier): switch to vendor agnostic constraints here... and cleanup
	// TODO(joelferrier): add tags for all the other data I didn't include...
	TagDiscovery                         = NewDataTag(ConstraintUnauthenticated, ConstraintReadOnly, 0x7E)
	TagBiometricInformationGroupTemplate = NewDataTag(ConstraintUnauthenticated, ConstraintReadOnly, 0x7F, 0x61)
	TagCardAuthentication                = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x01) // no overload
	TagCHUID                             = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x02) // no overload
	TagFingerprints                      = NewDataTag(ConstraintPIN, ConstraintManagementKey, 0x5F, 0xC1, 0x03)
	// 0x5F, 0xC1, 0x04
	TagAuthentication = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x05) // no overload
	TagSecurity       = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x06)
	TagCapability     = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x07) // no overload
	TagFacialImage    = NewDataTag(ConstraintPIN, ConstraintManagementKey, 0x5F, 0xC1, 0x08)
	TagPrinted        = NewDataTag(ConstraintPIN, ConstraintManagementKey, 0x5F, 0xC1, 0x09)
	TagSignature      = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x0A) // no overload
	TagKeyManagement  = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x0B) // no overload
	TagKeyHistory     = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x0C)
	// 0x5F, 0xC1, 0x0D <-> 0x5F, 0xC1, 0x20 (retired)
	TagIris                             = NewDataTag(ConstraintPIN, ConstraintManagementKey, 0x5F, 0xC1, 0x21)
	TagSecureMessagingCertificateSigner = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x22)
	TagPairingCodeReferenceData         = NewDataTag(ConstraintUnauthenticated, ConstraintManagementKey, 0x5F, 0xC1, 0x23)
)

func NewDataTag(get, put DataConstraint, id ...byte) DataTag {
	return DataTag{getConstraint: get, putConstraint: put, id: id}
}

type DataTag struct {
	id                           []byte
	putConstraint, getConstraint DataConstraint
}

func (t DataTag) String() string {
	return fmt.Sprintf("DataTag{id: 0x%X, get: %s, put: %s}", t.id, t.getConstraint, t.putConstraint)
}

func (t DataTag) TLV() (TypeLengthValue, error) {
	if len(t.id) == 0 || len(t.id) > 3 {
		return TypeLengthValue{}, ErrInvalidDataTag
	}

	// TAG_OBJ_DATA = 0x53
	// TAG_OBJ_ID = 0x5C

	// TODO(joelferrier): const
	return NewTLV(TagObjectID, t.id)
	// return t.key, nil
}

func (t DataTag) GetConstraint() (DataConstraint, error) {
	if t.getConstraint <= 0 || t.getConstraint > maxDataConstraint {
		return t.getConstraint, ErrInvalidDataTag
	}
	return t.getConstraint, nil
}

func (t DataTag) PutConstraint() (DataConstraint, error) {
	if t.putConstraint <= 0 || t.putConstraint > maxDataConstraint {
		return t.putConstraint, ErrInvalidDataTag
	}
	return t.putConstraint, nil
}
