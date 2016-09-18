package bsm

import (
	"bytes"
	"encoding/binary"
)

var SizeReturn int = 5

type Return struct {
	Status   byte   `json:"status" xml:"return>status"`
	Response uint32 `json:"response" xml:"return>response"`
}

// ParseReturn parses the return  object, can be variable length
func ParseReturn(buf *bytes.Buffer, tok *Token) error {
	r := Return{}
	data := readNextBytes(buf, SizeReturn)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &r)
	if err != nil {
		return err
	}
	// Set the header in the token
	tok.Return = r
	return nil
}
