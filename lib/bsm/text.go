package bsm

import (
	"bytes"
	"strings"
)

type Text struct {
	Length uint16 `json:"size" xml:"text>length"`
	Data   string `json:"data" xml:"text>data,inner"`
}

// ParseText parses the text object, can be variable length
func ParseText(buf *bytes.Buffer, tok *Token) error {
	text := Text{}
	text.Length = ReadUint16(buf)
	text.Data = strings.TrimSuffix(string(buf.Next(int(text.Length))), "\u0000")

	tok.Text = append(tok.Text, text)
	return nil
}
