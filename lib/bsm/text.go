package bsm

import "bytes"

type Text struct {
	Size uint16
	Data string
}

// ParseText parses the text object, can be variable length
func ParseText(buf *bytes.Buffer, tok *Token) error {
	tok.Text.Size = ReadUint16(buf)
	tok.Text.Data = string(buf.Next(int(tok.Text.Size)))
	return nil
}
