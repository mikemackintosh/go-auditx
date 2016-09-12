package main

// #include <bsm/libbsm.h>
// #include <sys/types.h>
import "C"

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

const AUDIT_PIPE = "/dev/auditpipe"
const AUDIT_EVENT_FILE = "/etc/security/audit_event"
const AUDIT_CLASS_FILE = "/etc/security/audit_class"
const AUDIT_CONTROL_FILE = "/etc/security/audit_control"
const AUDIT_USER_FILE = "/etc/security/audit_user"

const HEADER_LENGTH = 32
const SUBJECT_LENGTH = 36

func Btoi(array []byte) uint64 {
	var out uint64
	l := len(array)
	for i, b := range array {
		shift := uint64((l - i - 1) * 8)
		out |= uint64(b) << shift
	}
	return out
}

type AuditMsg struct {
	Raw     []byte
	Header  Header
	Subject Subject
}

type Header struct {
	Header        byte
	Count         uint64
	Version       byte
	EventType     uint64
	EventModifier uint64
	Seconds       uint64
	Milliseconds  uint64
}

/*
* euid                         4 bytes
* egid                         4 bytes
* ruid                         4 bytes
* rgid                         4 bytes
* pid                          4 bytes
* sessid                       4 bytes
* terminal ID
*   portid             4 bytes
*   machine id         4 bytes
 */
type Subject struct {
	AuditID   uint64
	Euid      uint64
	Egid      uint64
	Ruid      uint64
	Rgid      uint64
	Pid       uint64
	Sessid    uint64
	Portid    uint64
	Machineid uint64
}

func (msg *AuditMsg) Parse() {
	if err := msg.parseHeader(); err != nil {
		log.Printf("Error parsing header: %s", err)
	}

	if err := msg.parseSubject(); err != nil {
		log.Printf("Error parsing header: %s", err)
	}

	fmt.Printf("%+v", msg)

}

func (msg *AuditMsg) parseHeader() error {
	// Headers are 32 bytes long
	b := msg.Raw[:HEADER_LENGTH]
	msg.Header = Header{
		Header:        b[0],
		Count:         Btoi(b[1:5]),
		Version:       b[5],
		EventType:     Btoi(b[6:8]),
		EventModifier: Btoi(b[8:10]),
		Seconds:       Btoi(b[10:14]),
		Milliseconds:  Btoi(b[14:18]),
	}
	return nil
}

func (msg *AuditMsg) parseSubject() error {
	b := msg.Raw[(HEADER_LENGTH + 1):]
	msg.Subject = Subject{
		AuditID: Btoi(b[0:4]),
		Euid:    Btoi(b[5:9]),
		Egid:    Btoi(b[9:13]),
		Ruid:    Btoi(b[13:17]),
		Rgid:    Btoi(b[17:21]),
	}

	return nil
}

func main() {
	fmt.Println("==")

	fd, err := os.Open(AUDIT_PIPE)
	if err != nil {
		log.Printf("Err: %s", err)
	}
	defer fd.Close()

	stat, err := fd.Stat()
	fmt.Printf("Stat: %+v, err: %v", stat, err)
	/*conn, err := kernctl.NewConnByName("auditd")
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
	conn.Connect()
	defer conn.Close()
	//	conn.SendCommand(msg)
	for {
		m, err := conn.Select(2048)
		if err != nil {
			log.Printf("Error: %v\n", err)
		}
		log.Printf("MSG: %+v\n", string(m))
	}*/

	scanner := bufio.NewScanner(fd)

	onComma := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if data[len(data)-5] == 5 {
			return len(data), data, nil
		}
		// There is one final token to be delivered, which may be the empty string.
		// Returning bufio.ErrFinalToken here tells Scan there are no more tokens after this
		// but does not trigger an error to be returned from Scan itself.
		return 0, data, bufio.ErrFinalToken
	}
	scanner.Split(onComma)

	fmt.Println("Waiting")
	for scanner.Scan() {
		msg := &AuditMsg{Raw: scanner.Bytes()}
		msg.Parse()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

}
