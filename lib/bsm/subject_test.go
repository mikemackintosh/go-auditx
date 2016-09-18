package bsm

import (
	"bytes"
	"testing"
)

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
		ProcessID:   14696,
		SessionID:   100006,
		Terminal: struct {
			PortID    uint32
			MachineID [4]byte
		}{
			PortID:    114472,
			MachineID: [4]byte{0, 0, 0, 0},
		},
	}},
}

func TestParseSubject32(t *testing.T) {
	for i, tt := range subject32Test {
		token := &Token{}
		if err := ParseSubject32(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseSubject32(%d): failed parsing subject", i)
		}
		if token.Subject32 != tt.expected {
			t.Errorf("parseSubject32(%d): expected %+v, actual %+v", i, tt.expected, token.Subject32)
		}
	}
}
