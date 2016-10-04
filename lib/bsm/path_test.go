package bsm

import (
	"bytes"
	"testing"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

var pathBytes = []byte{0, 5, 81, 80, 84, 80}
var pathTest = []struct {
	byteBuffer *bytes.Buffer
	expected   Path
}{
	{bytes.NewBuffer(pathBytes), Path{
		Length: 5, Path: "QPTP",
	}},
}

func TestParsePath(t *testing.T) {
	for i, tt := range pathTest {
		token := &Token{}

		config.Debug = true

		if err := ParsePath(tt.byteBuffer, token); err != nil {
			t.Fatalf("parsePath(%d): failed parsing path", i)
		}
		if string(token.Path[0].Path) != string(tt.expected.Path) {
			t.Errorf("parsePath(%d): data expected %+v, actual %+v", i, []byte(tt.expected.Path), []byte(token.Path[0].Path))
		}
		if token.Path[0].Length != tt.expected.Length {
			t.Errorf("parsePath(%d): length expected %+v, actual %+v", i, tt.expected, token.Path)
		}

	}
}
