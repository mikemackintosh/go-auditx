package bsm

import (
	"bytes"
	"encoding/binary"
	"time"
)

// SizeHeader32 is the byte size of the header
var SizeHeader32 int = 17

// Header contains standard audit header tokens
type Header struct {
	Header32
	EventName string
}

type Header32 struct {
	RecordLength  uint32
	Version       byte
	EventType     uint16
	EventModifier uint16
	UnixTimestamp uint32
	Milliseconds  uint32
}

// Time generates a time.Time from the unix timestamp
func (h Header32) Time() time.Time {
	seconds := int64(h.UnixTimestamp)
	milliseconds := int64(h.Milliseconds)
	return time.Unix(seconds, milliseconds)
}

// ParseHeader32 parses header32 tokens
func ParseHeader32(buf *bytes.Buffer, tok *Token) error {
	h := Header32{}
	data := readNextBytes(buf, SizeHeader32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &h)
	if err != nil {
		return err
	}
	// Set the header in the token
	tok.Header = Header{Header32: h}
	tok.Header.EventName = EventTypes[h.EventType].Name
	return nil
}
