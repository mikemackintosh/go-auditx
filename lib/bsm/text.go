package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

type Text struct {
	Length uint16 `json:"size" xml:"text>length"`
	Data   string `json:"data" xml:"text>data,inner"`
}

// ParseText parses the text object, can be variable length
func ParseText(buf *bytes.Buffer, tok *Token) error {
	text := Text{}
	text.Length = ReadUint16(buf)
	textBytes := buf.Next(int(text.Length))

	text.Data = strings.TrimSuffix(string(textBytes), "\\u0000")

	if config.Debug {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, text.Length)
		fmt.Printf("> Bytes: %v %v", b, textBytes)
	}

	tok.Text = append(tok.Text, text)
	return nil
}
