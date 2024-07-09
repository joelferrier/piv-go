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

type CommandClass byte

const (
	StandardCommand CommandClass = 0x00
	ChainedCommand  CommandClass = 0x10
)

var (
	GetChunkedResponse = NewCommand(StandardCommand, InsGetResponse, EmptyParam, EmptyParam, nil)
)

type Command struct {
	cla  CommandClass
	ins  Instruction
	p1   Parameter
	p2   Parameter
	data []byte
}

// TODO consider aliasing []byte as a type like "type APDUMessage []byte"

// TODO(joelferrier): comment, encodes command as one or more APDU messages
// splitting messages automatically when maximum APDU message size is reached
// for a given payload.
func (c Command) Encode() [][]byte {
	const maxAPDUDataSize = 0xff

	data := c.data
	var cmds [][]byte

	// Chain commands for APDU payloads that exceed the APDU max message size.
	for len(data) > maxAPDUDataSize {
		req := make([]byte, 5+maxAPDUDataSize)
		req[0] = byte(ChainedCommand) // ISO/IEC 7816-4 5.1.1
		req[1] = byte(c.ins)
		req[2] = byte(c.p1)
		req[3] = byte(c.p2)
		req[4] = maxAPDUDataSize
		copy(req[5:], data[:maxAPDUDataSize])
		data = data[maxAPDUDataSize:]
		cmds = append(cmds, req)
	}

	// When the data fits within a single APDU (the final message) encode a single command
	// using the command message class.
	req := make([]byte, 5+len(c.data))
	req[0] = byte(c.cla)
	req[1] = byte(c.ins)
	req[2] = byte(c.p1)
	req[3] = byte(c.p2)
	req[4] = byte(len(data))
	copy(req[5:], data)
	cmds = append(cmds, req)

	return cmds
}

func (c Command) EncodeSingle() ([]byte, error) {
	cmds := c.Encode()
	if len(cmds) != 1 {
		return nil, fmt.Errorf("encoded command does not fit in single message, %d messages required", len(cmds)) // TODO(joelferrier): canonical error
	}
	return cmds[0], nil
}

func NewCommand(class CommandClass, ins Instruction, param1, param2 Parameter, data []byte) Command {
	return Command{cla: class, ins: ins, p1: param1, p2: param2, data: data}
}

type CommandResponse struct {
	Command Command
	Data    []byte
}
