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
	Header32  `json:"header" xml:"header"`
	EventName string    `json:"name" xml:"name"`
	Timestamp time.Time `json:"timestamp" xml:"timestamp"`
}

type Header32 struct {
	RecordLength  uint32 `json:"len" xml:"len"`
	Version       byte   `json:"version" xml:"version"`
	EventType     uint16 `json:"type" xml:"type"`
	EventModifier uint16 `json:"modifier" xml:"modifier"`
	UnixTimestamp uint32 `json:"unixtime" xml:"unixtime"`
	Milliseconds  uint32 `json:"milliseconds" xml:"milliseconds"`
}

// Timestamp generates a time.Time from the unix timestamp
func (h Header32) Timestamp() time.Time {
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
	// Set the timestamp
	timestamp := h.Timestamp()
	tok.Header.Timestamp = timestamp
	return nil
}
