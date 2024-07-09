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

package generic

import (
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv/protocol"
)

func init() {
	protocol.RegisterImpl(protocol.Generic, NewSmartCard)
}

func ListReaders() ([]string, error) {
	ctx, err := newSmartCardContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	return ctx.ListReaders()
}

type SmartCard struct {
	ctx    *smartCardContext
	handle *smartCardHandle
}

func NewSmartCard(reader string) (protocol.SmartCard, error) {
	// TODO(joelferrier): validate reader string

	ctx, err := newSmartCardContext()
	if err != nil {
		return nil, err
	}

	handle, err := ctx.Connect(reader)
	if err != nil {
		defer ctx.Close()
		return nil, err
	}

	return &SmartCard{ctx: ctx, handle: handle}, nil
}

// TODO(joelferrier): functions for PIN authentication? management key authentication?

// TAG_OBJ_DATA = 0x53
// TAG_OBJ_ID = 0x5C

// TODO(joelferrier): pass a parser implementation to GetData?
func (sc *SmartCard) GetData(tag protocol.DataTag) ([]byte, error) {
	// TODO(joelferrier): nil context check

	tlv, err := tag.TLV()
	if err != nil {
		return nil, err
	}
	_, err = tag.GetConstraint()
	if err != nil {
		return nil, err
	}
	// TODO(joelferrier): check get constraint
	resp, err := sc.Transmit(
		protocol.NewCommand(protocol.StandardCommand, protocol.InsGetData, protocol.ParamUNKNOWN1, protocol.ParamUNKNOWN2, tlv.Encode()),
	)
	if err != nil {
		return nil, err
	}
	if len(resp) != 0 {
		// TODO(joelferrier): return sentinel error?
		return nil, fmt.Errorf("TODO(joelferrier): better error")
	}

	return resp[0].Data, nil
}

func (sc *SmartCard) PutData(tag protocol.DataTag, data []byte) error {
	// TODO(joelferrier): nil context check

	tlv, err := tag.TLV()
	if err != nil {
		return err
	}
	_, err = tag.PutConstraint()
	if err != nil {
		return err
	}
	// TODO(joelferrier): check put constraint
	// Tlv(TAG_OBJ_ID, int2bytes(object_id)) + Tlv(TAG_OBJ_DATA, data or b""),
	hdr := tlv.Encode()
	// TODO(joelferrier): const instead of magic value 0x53
	obj, err := protocol.NewTLV(protocol.TagObjectData, data)
	if err != nil {
		return err
	}
	buf := obj.Encode()
	msg := make([]byte, len(hdr)+len(buf))
	copy(msg[:len(hdr)], hdr)
	copy(msg[len(hdr):], buf)

	_, err = sc.Transmit(
		// TODO(joelferrier): swap out undocumented parameters
		protocol.NewCommand(protocol.StandardCommand, protocol.InsPutData, protocol.ParamUNKNOWN1, protocol.ParamUNKNOWN2, msg),
	)

	return err
}

// TODO(joelferrier): note in the doc comment that all commands are transmitted in a single transaction.
// TODO(joelferrier): take a variadic slice of APDU commands
func (sc *SmartCard) Transmit(cmds ...protocol.Command) ([]protocol.CommandResponse, error) {
	// TODO(joelferrier): nil context check
	if len(cmds) == 0 {
		//TODO(joelferrier): return sentinel error (invalid command)
		return nil, fmt.Errorf("TODO(joelferrier): invalid cmd")
	}

	tx, err := sc.handle.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()

	var responses []protocol.CommandResponse
	for _, cmd := range cmds {
		resp, err := tx.Transmit(cmd)
		if err != nil {
			return nil, err
		}
		responses = append(responses, protocol.CommandResponse{
			Command: cmd,
			Data:    resp,
		})
	}

	return responses, nil
}

func (sc *SmartCard) Close() error {
	hErr := sc.handle.Close()
	cErr := sc.ctx.Close()

	sc.ctx = nil
	sc.handle = nil

	if hErr == nil {
		return cErr
	}
	return hErr
}

func (sc *SmartCard) Certificate() {

}

func (sc *SmartCard) PrivateKey() {

}

func (sc *SmartCard) Retries() {

}

func (sc *SmartCard) SetCertificate() {

}

func (sc *SmartCard) SetManagementKey() {

}

func (sc *SmartCard) SetPIN() {

}
func (sc *SmartCard) SetPUK() {

}
func (sc *SmartCard) SetPrivateKeyInsecure() {

}
func (sc *SmartCard) Unblock() {

}
func (sc *SmartCard) VerifyPIN() {

}

// vendor specific extensions below
// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html

func (sc *SmartCard) Attest() (*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc *SmartCard) AttestationCertificate() (*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc *SmartCard) Reset() error {
	return fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc SmartCard) Serial() (uint32, error) {
	return 0, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}

func (sc SmartCard) Version() (protocol.Version, error) {
	return protocol.Version{}, fmt.Errorf("unimplemented") // TODO(joelferrier): canonical error
}
