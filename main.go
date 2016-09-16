package main

/*
#include <bsm/libbsm.h>
#include <sys/types.h>
*/
import "C"

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"bytes"
)

const (
	AUT_INVALID      = 0x00
	AUT_OTHER_FILE32 = 0x11
	AUT_OHEADER      = 0x12
	AUT_TRAILER      = 0x13
	AUT_HEADER32     = 0x14
	AUT_HEADER32_EX  = 0x15
	AUT_DATA         = 0x21
	AUT_IPC          = 0x22
	AUT_PATH         = 0x23
	AUT_SUBJECT32    = 0x24
	AUT_XATPATH      = 0x25
	AUT_PROCESS32    = 0x26
	AUT_RETURN32     = 0x27
	AUT_TEXT         = 0x28
	AUT_OPAQUE       = 0x29
	AUT_IN_ADDR      = 0x2a
	AUT_IP           = 0x2b
	AUT_IPORT        = 0x2c
	AUT_ARG32        = 0x2d
	AUT_SOCKET       = 0x2e
	AUT_SEQ          = 0x2f
	AUT_ACL          = 0x30
	AUT_ATTR         = 0x31
	AUT_IPC_PERM     = 0x32
	AUT_LABEL        = 0x33
	AUT_GROUPS       = 0x34
	AUT_ACE          = 0x35
	AUT_PRIV         = 0x38
	AUT_UPRIV        = 0x39
	AUT_LIAISON      = 0x3a
	AUT_NEWGROUPS    = 0x3b
	AUT_EXEC_ARGS    = 0x3c
	AUT_EXEC_ENV     = 0x3d
	AUT_ATTR32       = 0x3e
	AUT_UNAUTH       = 0x3f
	AUT_XATOM        = 0x40
	AUT_XOBJ         = 0x41
	AUT_XPROTO       = 0x42
	AUT_XSELECT      = 0x43
	AUT_XCOLORMAP    = 0x44
	AUT_XCURSOR      = 0x45
	AUT_XFONT        = 0x46
	AUT_XGC          = 0x47
	AUT_XPIXMAP      = 0x48
	AUT_XPROPERTY    = 0x49
	AUT_XWINDOW      = 0x4a
	AUT_XCLIENT      = 0x4b
	AUT_CMD          = 0x51
	AUT_EXIT         = 0x52
	AUT_ZONENAME     = 0x60
	AUT_HOST         = 0x70
	AUT_ARG64        = 0x71
	AUT_RETURN64     = 0x72
	AUT_ATTR64       = 0x73
	AUT_HEADER64     = 0x74
	AUT_SUBJECT64    = 0x75
	AUT_PROCESS64    = 0x77
	AUT_OTHER_FILE64 = 0x78
	AUT_HEADER64_EX  = 0x79
	AUT_SUBJECT32_EX = 0x7a
	AUT_PROCESS32_EX = 0x7b
	AUT_SUBJECT64_EX = 0x7c
	AUT_PROCESS64_EX = 0x7d
	AUT_IN_ADDR_EX   = 0x7e
	AUT_SOCKET_EX    = 0x7f
)

const (
	AUDIT_PIPE         = "/dev/auditpipe"
	AUDIT_EVENT_FILE   = "/etc/security/audit_event"
	AUDIT_CLASS_FILE   = "/etc/security/audit_class"
	AUDIT_CONTROL_FILE = "/etc/security/audit_control"
	AUDIT_USER_FILE    = "/etc/security/audit_user"
)

type Token struct {
	Header32
	Header64
	Subject32
	Text
}
type Header32 struct {
	Type          byte
	RecordLength  uint32
	Version       uint16
	EventType     uint16
	EventModifier uint16
	UnixTimestamp uint32
	Milliseconds  uint32
	Timestamp     time.Time
}

type Header64 struct {
	Type          byte
	RecordLength  uint32
	Version       uint16
	EventType     uint16
	EventModifier uint16
	UnixTimestamp uint64
	Milliseconds  uint64
	Timestamp     time.Time
}

type Subject32 struct {
	Type        byte
	AuditUserID uint32
	UserID      uint32
	GroupID     uint32
	RealUID     uint32
	RealGID     uint32
	ProcessID   uint32
	SessionID   uint32
	Terminal    struct {
		PortID    uint32
		MachineID []byte
	}
}

type Text struct {
	Type byte
	Size uint16
	Data string
}

func init() {

}

func main() {
	flag.Parse()

	eventDefinitions, err := ParseEventsFile(AUDIT_EVENT_FILE)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v", eventDefinitions)

	fmt.Println("==")

	fd, err := os.Open(AUDIT_PIPE)
	if err != nil {
		log.Printf("Err: %s", err)
	}
	defer fd.Close()

	//stat, err := fd.Stat()
	scanner := bufio.NewScanner(fd)

	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if data[len(data)-5] == 5 {
			return len(data), data, nil
		}
		return 0, data, bufio.ErrFinalToken
	})

	fmt.Println("Waiting")
	for scanner.Scan() {
		// Read the scanner into a byte.Buffer
		buf := bytes.NewBuffer(scanner.Bytes())

		var reclen uint32
		var eventType byte
		token := &Token{}

		for reclen = uint32(buf.Len()); reclen > 0; reclen, eventType, _ = parseRecord(buf) {
			switch eventType {
			case AUT_HEADER32:
				token.Header32 = Header32{Type: eventType}
				if err := parseHeader32(buf, token, reclen); err != nil {
					fmt.Printf("Header parsing error: %+s", err)
				}
			case AUT_SUBJECT32:
				token.Subject32 = Subject32{Type: eventType}
				if err := parseSubject32(buf, token, reclen); err != nil {
					fmt.Printf("Header parsing error: %+s", err)
				}
			case AUT_TEXT:
				token.Text = Text{Type: eventType}
				if err := parseText(buf, token); err != nil {
					fmt.Printf("Header parsing error: %+s", err)
				}
			}

			//fmt.Printf("> (%d) %+v", 1, b)
		}
		fmt.Printf("%+v", token)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const suint32 = C.sizeof_u_int32_t
const suint16 = C.sizeof_u_int16_t
const schar = 1

func parseRecord(buf *bytes.Buffer) (uint32, byte, error) {
	var reclen uint32

	// Grab the first byte, determine the type
	eventType, err := buf.ReadByte()
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	fmt.Printf("Found new evnet type of: %+v\n\n", eventType)

	switch eventType {
	case AUT_HEADER32,
		AUT_HEADER32_EX,
		AUT_HEADER64,
		AUT_HEADER64_EX:

		// Read the next few bytes of the header token
		// Get the record length
		reclen = binary.BigEndian.Uint32(buf.Next(suint32))

		break

	case AUT_OTHER_FILE32:
		if sec := binary.BigEndian.Uint32(buf.Next(suint32)); sec < suint32 {
			return 0, eventType, nil
		}

		_ = binary.BigEndian.Uint32(buf.Next(suint32))
		filenamelen := binary.BigEndian.Uint16(buf.Next(suint16))
		reclen = uint32(schar + suint32 + suint32 + suint16 + filenamelen)
		break
	default:
		reclen = uint32(buf.Len())
	}

	return reclen, eventType, nil
}

func parseHeader32(buf *bytes.Buffer, tok *Token, reclen uint32) error {
	tok.Header32.RecordLength = reclen
	tok.Header32.Version = ByteToInt16(buf.Next(1))
	tok.Header32.EventType = binary.BigEndian.Uint16(buf.Next(C.sizeof_u_int16_t))
	tok.Header32.EventModifier = binary.BigEndian.Uint16(buf.Next(C.sizeof_u_int16_t))
	tok.Header32.UnixTimestamp = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Header32.Milliseconds = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Header32.Timestamp = time.Unix(int64(tok.Header32.UnixTimestamp), int64(tok.Header32.Milliseconds))
	return nil
}

func parseSubject32(buf *bytes.Buffer, tok *Token, reclen uint32) error {
	tok.Subject32.AuditUserID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.UserID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.GroupID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.RealUID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.RealGID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.ProcessID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.SessionID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.Terminal.PortID = binary.BigEndian.Uint32(buf.Next(C.sizeof_u_int32_t))
	tok.Subject32.Terminal.MachineID = buf.Next(C.sizeof_u_int32_t)
	return nil
}

func parseText(buf *bytes.Buffer, tok *Token) error {
	tok.Text.Size = binary.BigEndian.Uint16(buf.Next(C.sizeof_u_int16_t))
	tok.Text.Data = string(buf.Next(int(tok.Text.Size)))
	return nil
}

func ByteToInt64(array []byte) uint64 {
	var out uint64
	l := len(array)
	for i, b := range array {
		shift := uint64((l - i - 1) * 8)
		out |= uint64(b) << shift
	}
	return out
}

func ByteToInt32(array []byte) uint32 {
	var out uint32
	l := len(array)
	for i, b := range array {
		shift := uint32((l - i - 1) * 8)
		out |= uint32(b) << shift
	}
	return out
}

func ByteToInt16(array []byte) uint16 {
	var out uint16
	l := len(array)
	for i, b := range array {
		shift := uint16((l - i - 1) * 8)
		out |= uint16(b) << shift
	}
	return out
}

type EventsDictionary map[uint16]EventDefinition
type EventDefinition struct {
	ID       uint16
	Constant string
	Name     string
	Flag     []string
}

func ParseEventsFile(eventsFile string) (EventsDictionary, error) {
	var ed = EventsDictionary{}

	if _, err := os.Stat(eventsFile); err == nil {
		file, err := os.Open(eventsFile)
		if err != nil {
			return ed, fmt.Errorf("No events file found.")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// trim the line from all leading whitespace first
			line := strings.TrimLeft(scanner.Text(), " \t")
			// line is not empty, and not starting with '#'
			if len(line) > 0 && !strings.HasPrefix(line, "#") {
				event := strings.SplitN(line, ":", 4)
				if len(event) == 4 {
					eventID, _ := strconv.ParseInt(event[0], 10, 16)
					eid := uint16(eventID)
					definition := EventDefinition{
						ID:       eid,
						Constant: event[1],
						Name:     event[2],
						Flag:     strings.Split(event[3], ","),
					}
					ed[eid] = definition
				}
			}
		}

		// If there was an error running scan, then return
		if err := scanner.Err(); err != nil {
			return ed, fmt.Errorf("Unable to read events file.")
		}
	}

	return ed, nil
}
