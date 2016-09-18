package bsm

import (
	"bytes"
	"testing"
)

var returnBytes = []byte{255, 0, 0, 16, 6}
var returnTest = []struct {
	byteBuffer *bytes.Buffer
	expected   Return
}{
	{bytes.NewBuffer(returnBytes), Return{
		Status: 255, Response: 4102,
	}},
}

func TestParseReturn(t *testing.T) {
	for i, tt := range returnTest {
		token := &Token{}
		if err := ParseReturn(tt.byteBuffer, token); err != nil {
			t.Fatalf("parseReturn(%d): failed parsing return", i)
		}
		if token.Return != tt.expected {
			t.Errorf("parseReturn(%d): expected %+v, actual %+v", i, tt.expected, token.Text)
		}

	}
}
