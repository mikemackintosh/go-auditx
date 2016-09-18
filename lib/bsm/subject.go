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
	AuditUserID uint32 `json:"audituid" xml:"subject>audituid"`
	UserID      uint32 `json:"uid" xml:"subject>uid"`
	GroupID     uint32 `json:"gid" xml:"subject>gid"`
	RealUID     uint32 `json:"ruid" xml:"subject>ruid"`
	RealGID     uint32 `json:"rgid" xml:"subject>rgid"`
	ProcessID   uint32 `json:"pid" xml:"subject>pid"`
	SessionID   uint32 `json:"sessionid" xml:"subject>sessionid"`
	Terminal    struct {
		PortID    uint32  `json:"port" xml:"port"`
		MachineID [4]byte `json:"machine" xml:"machine"`
	} `json:"terminal" xml:"subject>terminal"`
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
