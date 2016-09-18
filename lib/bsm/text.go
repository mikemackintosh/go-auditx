package bsm

import (
	"bytes"
	"strings"
)

type Text struct {
	Size uint16 `json:"size" xml:"text>size"`
	Data string `json:"data" xml:"text>data,inner"`
}

// ParseText parses the text object, can be variable length
func ParseText(buf *bytes.Buffer, tok *Token) error {
	tok.Text.Size = ReadUint16(buf)
	tok.Text.Data = strings.TrimSuffix(string(buf.Next(int(tok.Text.Size))), "\u0000")
	return nil
}
