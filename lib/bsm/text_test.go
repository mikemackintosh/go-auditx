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
		Size: 5, Data: "QPTP",
	}},
}

func TestParseText(t *testing.T) {
	for i, tt := range textTest {
		token := &Token{}
		if err := ParseText(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseText(%d): failed parsing text", i)
		}
		if string(token.Text.Data) != string(tt.expected.Data) {
			t.Errorf("parseText(%d): data expected %+v, actual %+v", i, []byte(tt.expected.Data), []byte(token.Text.Data))
		}
		if token.Text.Size != tt.expected.Size {
			t.Errorf("parseText(%d): size expected %+v, actual %+v", i, tt.expected, token.Text)
		}
	}
}
