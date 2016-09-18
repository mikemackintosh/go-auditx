package bsm

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
		if err := ParseHeader32(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseHeader32(%d): failed parsing header", i)
		}
		if token.Header32 != tt.expected {
			t.Errorf("parseHeader32(%d): expected %+v, actual %+v", i, tt.expected, token.Header32)
		}
	}
}
