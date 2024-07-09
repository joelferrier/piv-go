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

package piv

import (
	"strings"

	"github.com/go-piv/piv-go/v2/piv/internal/generic"
	"github.com/go-piv/piv-go/v2/piv/protocol"

	// Register protocol.SmartCart implementations.
	// Note: a blank import for "github.com/go-piv/piv-go/v2/piv/internal/generic" is
	// not required as methods from the generic package are to enumerate connected
	// smart cards.
	_ "github.com/go-piv/piv-go/v2/piv/internal/trussed"
	_ "github.com/go-piv/piv-go/v2/piv/internal/yubikey"
)

const (
	GenericSmartCard  = protocol.Generic
	YubikeySmartCard  = protocol.YubiKey
	SoloKeySmartCard  = protocol.SoloKey
	NitroKeySmartCard = protocol.NitroKey
)

// TODO(joelferrier): alias protocol canonical errors here? or leave in protocol?

type SmartCard struct {
	Name string
	Type protocol.SmartCardType
}

func Cards() ([]SmartCard, error) {
	names, err := generic.ListReaders()
	if err != nil {
		return nil, err
	}
	var cards []SmartCard
	for _, name := range names {
		cards = append(cards, SmartCard{
			Name: name,
			Type: matchCard(name),
		})
	}
	return cards, nil
}

func matchCard(name string) protocol.SmartCardType {
	switch {
	case strings.Contains(strings.ToLower(name), "yubikey"):
		return YubikeySmartCard
	case strings.Contains(strings.ToLower(name), "solokey"):
		return SoloKeySmartCard
	case strings.Contains(strings.ToLower(name), "nitrokey"):
		return NitroKeySmartCard
	default:
		return GenericSmartCard
	}
}

func Open(sc SmartCard) (protocol.SmartCard, error) {
	factory, err := protocol.GetFactory(sc.Type)
	if err != nil {
		return nil, err
	}
	return factory(sc.Name)
}

// TODO(joelferrier): revisit if this is a useful method, can also be achieved by
// explicitely setting the generic type in Open().
func OpenGeneric(sc SmartCard) (protocol.SmartCard, error) {
	factory, err := protocol.GetFactory(protocol.Generic)
	if err != nil {
		return nil, err
	}
	return factory(sc.Name)
}
