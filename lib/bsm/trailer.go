package bsm

import (
	"bytes"
	"encoding/binary"
)

// SizeTrailer is the byte size of the trailer
var SizeTrailer int = 6

// Trailer contains standard audit trailer tokens
type Trailer struct {
	Magic uint16 `json:"magic" xml:"trailer>magic"`
	Count uint32 `json:"count" xml:"trailer>count"`
}

// ParseTrailer parses trailer tokens
func ParseTrailer(buf *bytes.Buffer, tok *Token) error {
	t := Trailer{}
	data := readNextBytes(buf, SizeTrailer)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &t)
	if err != nil {
		return err
	}
	// Set the trailer in the token
	tok.Trailer = t
	return nil
}
