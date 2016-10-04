package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

type Path struct {
	Length uint16 `json:"size" xml:"path>length"`
	Path   string `json:"path" xml:"path>path,inner"`
}

// ParsePath parses the path object, can be variable length
func ParsePath(buf *bytes.Buffer, tok *Token) error {
	path := Path{}
	path.Length = ReadUint16(buf)
	pathBytes := buf.Next(int(path.Length))
	path.Path = strings.TrimSuffix(string(pathBytes), "\\u0000")

	if config.Debug {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, path.Length)
		fmt.Printf("> Bytes: %v %v", b, pathBytes)
	}

	tok.Path = append(tok.Path, path)
	return nil
}
