package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

type Arg struct {
	Number byte   `json:"size" xml:"arg>size"`
	Value  uint64 `json:"value" xml:"arg>value"`
	Length uint16 `json:"length" xml:"arg>length"`
	Text   string `json:"text" xml:"arg>text"`
}

var SizeofArg64 int = 11

type Arg64 struct {
	Number byte   `json:"size" xml:"arg>size"`
	Value  uint64 `json:"value" xml:"arg>value"`
	Length uint16 `json:"length" xml:"arg>length"`
}

var SizeofArg32 int = 7

type Arg32 struct {
	Number byte   `json:"size" xml:"arg>size"`
	Value  uint32 `json:"value" xml:"arg>value"`
	Length uint16 `json:"length" xml:"arg>length"`
}

type ArgText struct {
	Text string `json:"text" xml:"arg>text"`
}

// ParseArg parses the arg object, can be variable length
func ParseArg32(buf *bytes.Buffer, tok *Token) error {
	a := Arg32{}

	data := readNextBytes(buf, SizeofArg32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &a)
	if err != nil {
		return err
	}

	text := string(readNextBytes(buf, int(a.Length)))

	// Set the header in the token
	arg := Arg{
		Number: a.Number,
		Value:  uint64(a.Value),
		Length: a.Length,
		Text:   text,
	}
	tok.Arg = append(tok.Arg, arg)

	if config.Debug {
		fmt.Printf("> Buffer: %+v", data)
		fmt.Printf("> Struct: %+v", a)
	}

	return nil
}

// ParseArg64 parses the arg object, can be variable length
func ParseArg64(buf *bytes.Buffer, tok *Token) error {
	a := Arg64{}

	data := readNextBytes(buf, SizeofArg64)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &a)
	if err != nil {
		return err
	}

	text := string(readNextBytes(buf, int(a.Length)))

	// Set the header in the token
	arg := Arg{
		Number: a.Number,
		Value:  uint64(a.Value),
		Length: a.Length,
		Text:   text,
	}
	tok.Arg = append(tok.Arg, arg)

	if config.Debug {
		fmt.Printf("> Buffer: %+v", data)
		fmt.Printf("> Struct: %+v", a)
	}
	return nil
}
