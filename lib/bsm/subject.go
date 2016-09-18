package bsm

import (
	"bytes"
	"encoding/binary"
)

var SizeSubject32 int = 36

type Subject struct {
	Subject32
}

type Subject32 struct {
	AuditUserID uint32
	UserID      uint32
	GroupID     uint32
	RealUID     uint32
	RealGID     uint32
	ProcessID   uint32
	SessionID   uint32
	Terminal    struct {
		PortID    uint32
		MachineID [4]byte
	}
}

// ParseSubject32 parses the user/actor subject
func ParseSubject32(buf *bytes.Buffer, tok *Token) error {
	subject := Subject32{}
	data := readNextBytes(buf, SizeSubject32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &subject)
	if err != nil {
		return err
	}
	// Set the subject in the token
	tok.Subject = Subject{Subject32: subject}
	return nil
}
