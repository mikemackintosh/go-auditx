package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Arg struct {
	Arg64
}

var SizeofArg64 int = 11

type Arg64 struct {
	Number byte   `json:"size" xml:"arg>size"`
	Value  uint64 `json:"value" xml:"arg>value"`
	Length uint16 `json:"length" xml:"arg>length"`
	Text   string
}

type ArgText struct {
	Text string `json:"text" xml:"arg>text"`
}

// ParseArg parses the arg object, can be variable length
func ParseArg(buf *bytes.Buffer, tok *Token) error {
	a := Arg64{}

	data := readNextBytes(buf, SizeofArg64)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &a)
	if err != nil {
		return err
	}

	text := string(readNextBytes(buf, int(a.Length)))

	// Set the header in the token
	tok.Arg = Arg{Arg64: a}
	tok.Arg.Text = text
	fmt.Printf("Buffer: %+v", data)
	fmt.Printf("Struct: %+v", a)
	return nil
}
