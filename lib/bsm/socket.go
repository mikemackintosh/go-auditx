package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

var SizeofSocket int = 18

type Socket struct {
	Domain        uint16 `json:"sock_domain,omitempty" xml:"socket>sock_domain"`
	SocketType    uint16 `json:"sock_type,omitempty" xml:"socket>sock_type"`
	AddressType   uint16 `json:"addr_type,omitempty" xml:"socket>addr_type"`
	LocalPort     uint16 `json:"local_port,omitempty" xml:"socket>local_port"`
	LocalAddress  uint16 `json:"local_address,omitempty" xml:"socket>local_address"`
	RemotePort    uint16 `json:"report_port,omitempty" xml:"socket>report_port"`
	RemoteAddress uint16 `json:"remote_address,omitempty" xml:"socket>remote_address"`
}

// ParseSocket parses the socket object, can be variable length
func ParseSocket(buf *bytes.Buffer, tok *Token) error {
	s := Socket{}

	data := readNextBytes(buf, SizeofSocket)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &s)
	if err != nil {
		return err
	}

	// Set the header in the token
	tok.Socket = s

	if config.Debug {
		fmt.Printf("> Buffer: %+v", data)
		fmt.Printf("> Struct: %+v", s)
	}

	return nil
}
