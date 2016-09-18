package main

import (
	"bytes"
	"testing"
)

// parseHeader32
var header32Bytes = []byte{0, 0, 0, 127, 11, 24, 63, 0, 0, 87, 221, 212, 203, 0, 0, 1, 253}

var header32Test = []struct {
	byteBuffer *bytes.Buffer
	expected   Header32
}{
	{bytes.NewBuffer(header32Bytes), Header32{
		RecordLength:  127,
		Version:       11,
		EventType:     6207,
		EventModifier: 0,
		UnixTimestamp: 1474155723,
		Milliseconds:  509,
	}},
}

func TestParseHeader32(t *testing.T) {
	for i, tt := range header32Test {
		token := &Token{}
		if err := parseHeader32(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseHeader32(%d): failed parsing header", i)
		}
		if token.Header32 != tt.expected {
			t.Errorf("parseHeader32(%d): expected %+v, actual %+v", i, tt.expected, token.Header32)
		}
	}
}

var subject32Bytes = []byte{0, 0, 1, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 104, 0, 1, 134, 166, 0, 1, 191, 40, 0, 0, 0, 0}
var subject32Test = []struct {
	byteBuffer *bytes.Buffer
	expected   Subject32
}{
	{bytes.NewBuffer(subject32Bytes), Subject32{
		AuditUserID: 501,
		UserID:      0,
		GroupID:     0,
		RealUID:     0,
		RealGID:     0,
		ProcessID:   16119,
		SessionID:   100006,
		Terminal: {
			PortID:    115895,
			MachineID: []byte{0, 0, 0, 0},
		},
	}},
}

func TestParseSubject32(t *testing.T) {
	for i, tt := range subject32Test {
		token := &Token{}
		if err := parseHeader32(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseSubject32(%d): failed parsing header", i)
		}
		if token.Subject32 != tt.expected {
			t.Errorf("parseSubject32(%d): expected %+v, actual %+v", i, tt.expected, token.Subject32)
		}
	}
}
