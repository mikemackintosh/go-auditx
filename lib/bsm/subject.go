package bsm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/mikemackintosh/go-auditx/lib/config"
)

var SizeSubject32 int = 36

type Subject struct {
	AuditUserID uint32   `json:"audituid" xml:"subject>audituid"`
	UserID      uint32   `json:"uid" xml:"subject>uid"`
	GroupID     uint32   `json:"gid" xml:"subject>gid"`
	RealUID     uint32   `json:"ruid" xml:"subject>ruid"`
	RealGID     uint32   `json:"rgid" xml:"subject>rgid"`
	ProcessID   uint32   `json:"pid" xml:"subject>pid"`
	SessionID   uint32   `json:"sessionid" xml:"subject>sessionid"`
	Terminal    Terminal `json:"terminal" xml:"subject>terminal"`
}
type Terminal struct {
	PortID    uint32  `json:"port" xml:"port"`
	Type      uint32  `json:"type,omitempty" xml:"type"`
	MachineID [4]byte `json:"machine" xml:"machine"`
}

type Subject32 struct {
	AuditUserID uint32     `json:"audituid" xml:"subject>audituid"`
	UserID      uint32     `json:"uid" xml:"subject>uid"`
	GroupID     uint32     `json:"gid" xml:"subject>gid"`
	RealUID     uint32     `json:"ruid" xml:"subject>ruid"`
	RealGID     uint32     `json:"rgid" xml:"subject>rgid"`
	ProcessID   uint32     `json:"pid" xml:"subject>pid"`
	SessionID   uint32     `json:"sessionid" xml:"subject>sessionid"`
	Terminal    Terminal32 `json:"terminal" xml:"subject>terminal"`
}

type Terminal32 struct {
	PortID    uint32  `json:"port" xml:"port"`
	MachineID [4]byte `json:"machine" xml:"machine"`
}

var SizeSubject32ex int = 40

type Subject32ex struct {
	AuditUserID uint32     `json:"audituid" xml:"subject>audituid"`
	UserID      uint32     `json:"uid" xml:"subject>uid"`
	GroupID     uint32     `json:"gid" xml:"subject>gid"`
	RealUID     uint32     `json:"ruid" xml:"subject>ruid"`
	RealGID     uint32     `json:"rgid" xml:"subject>rgid"`
	ProcessID   uint32     `json:"pid" xml:"subject>pid"`
	SessionID   uint32     `json:"sessionid" xml:"subject>sessionid"`
	Terminal    Terminalex `json:"terminal" xml:"subject>terminal"`
}

type Terminalex struct {
	PortID    uint32  `json:"port" xml:"port"`
	Type      uint32  `json:"type,omitempty" xml:"type"`
	MachineID [4]byte `json:"machine" xml:"machine"`
}

// ParseSubject32 parses the user/actor subject
func ParseSubject32(buf *bytes.Buffer, tok *Token) error {
	s := Subject32{}
	data := readNextBytes(buf, SizeSubject32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &s)
	if err != nil {
		return err
	}

	if config.Debug {
		fmt.Printf("> \tBytes: %v\n", data)
	}

	// Set the subject in the token
	tok.Subject = Subject{
		AuditUserID: s.AuditUserID,
		UserID:      s.UserID,
		GroupID:     s.GroupID,
		RealUID:     s.RealUID,
		RealGID:     s.RealGID,
		ProcessID:   s.ProcessID,
		SessionID:   s.SessionID,
		Terminal: Terminal{
			PortID:    s.Terminal.PortID,
			MachineID: s.Terminal.MachineID,
		},
	}

	return nil
}

// ParseSubject32ex parses the user/actor subject
func ParseSubject32ex(buf *bytes.Buffer, tok *Token) error {
	s := Subject32ex{}
	data := readNextBytes(buf, SizeSubject32ex)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &s)
	if err != nil {
		return err
	}

	if config.Debug {
		fmt.Printf("> Bytes: %v", data)
	}

	// Set the subject in the token
	tok.Subject = Subject{
		AuditUserID: s.AuditUserID,
		UserID:      s.UserID,
		GroupID:     s.GroupID,
		RealUID:     s.RealUID,
		RealGID:     s.RealGID,
		ProcessID:   s.ProcessID,
		SessionID:   s.SessionID,
		Terminal: Terminal{
			PortID:    s.Terminal.PortID,
			Type:      s.Terminal.Type,
			MachineID: s.Terminal.MachineID,
		},
	}

	return nil
}
