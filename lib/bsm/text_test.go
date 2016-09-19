package bsm

import (
	"bytes"
	"testing"
)

var textBytes = []byte{0, 5, 81, 80, 84, 80}
var textTest = []struct {
	byteBuffer *bytes.Buffer
	expected   Text
}{
	{bytes.NewBuffer(textBytes), Text{
		Length: 5, Data: "QPTP",
	}},
}

func TestParseText(t *testing.T) {
	for i, tt := range textTest {
		token := &Token{}
		if err := ParseText(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseText(%d): failed parsing text", i)
		}
		if string(token.Text[0].Data) != string(tt.expected.Data) {
			t.Errorf("parseText(%d): data expected %+v, actual %+v", i, []byte(tt.expected.Data), []byte(token.Text[0].Data))
		}
		if token.Text[0].Length != tt.expected.Length {
			t.Errorf("parseText(%d): length expected %+v, actual %+v", i, tt.expected, token.Text)
		}
	}
}
