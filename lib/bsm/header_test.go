package bsm

import (
	"bytes"
	"testing"
	"time"
)

// parseHeader32
var header32Bytes = []byte{0, 0, 0, 127, 11, 24, 63, 0, 0, 87, 221, 212, 203, 0, 0, 1, 253}

//var timestamp = "2016-09-17 16:42:03.000000509 -0700 PDT"

var header32Test = []struct {
	byteBuffer *bytes.Buffer
	expected   Header
}{
	{bytes.NewBuffer(header32Bytes), Header{
		RecordLength:  127,
		Version:       11,
		EventType:     6207,
		EventModifier: 0,
		UnixTimestamp: 1474155723,
		Milliseconds:  509,
		EventName:     "create user",
	}},
}

func TestParseHeader32(t *testing.T) {
	for i, tt := range header32Test {
		token := &Token{}
		if err := ParseHeader32(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseHeader32(%d): failed parsing header", i)
		}

		timestampFmt := "2006-01-02T15:04:05.999999-07:00"
		str := "2016-09-17T16:42:03.000000509-07:00"
		parsedTimestamp, _ := time.Parse(timestampFmt, str)
		tt.expected.Timestamp = parsedTimestamp

		if token.Header != tt.expected {
			t.Errorf("parseHeader32(%d): expected %+v, actual %+v", i, tt.expected, token.Header)
		}
	}
}
