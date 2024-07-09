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
	"fmt"
	"log"
)

type SmartCardType int

func (t SmartCardType) String() string {
	switch t {
	case Generic:
		return "Generic"
	case YubiKey:
		return "YubiKey"
	case SoloKey:
		return "SoloKey"
	case NitroKey:
		return "NitoKey"
	default:
		return fmt.Sprintf("UnknownSmartCardType(%d)", t)
	}
}

const (
	Generic SmartCardType = iota
	YubiKey
	SoloKey
	NitroKey
)

type Factory func(reader string) (SmartCard, error)

var implementations = make(map[SmartCardType]Factory)

func RegisterImpl(typ SmartCardType, open Factory) {
	if _, ok := implementations[typ]; ok {
		log.Fatalf("Register(%v, _) duplicate SmartCardType registration", typ)
	}
	implementations[typ] = open
}

func GetFactory(typ SmartCardType) (Factory, error) {
	f, ok := implementations[typ]
	if !ok {
		// TODO(joelferrier): return error
		return nil, fmt.Errorf("factory not found") // TODO(joelferrier): canonical error
	}
	return f, nil
}
