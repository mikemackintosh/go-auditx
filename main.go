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

var debug bool = false

type Token struct {
	Header32
	Header64
	Subject32
	Text
}

// SizeHeader32 is the byte size of the header
var SizeHeader32 int = 17

// Header32 contains standard audit header tokens
type Header32 struct {
	RecordLength  uint32
	Version       byte
	EventType     uint16
	EventModifier uint16
	UnixTimestamp uint32
	Milliseconds  uint32
}

// Time generates a time.Time from the unix timestamp
func (h Header32) Time() time.Time {
	seconds := int64(h.UnixTimestamp)
	milliseconds := int64(h.Milliseconds)
	return time.Unix(seconds, milliseconds)
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

var SizeSubject32 int = 36

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

type Text struct {
	Size uint16
	Data string
}

type Return32 struct {
	Status byte
	Value  uint32
}

func init() {
	flag.BoolVar(&debug, "d", false, "Enable for debug")
}

func main() {
	flag.Parse()

	/*eventDefinitions, err := ParseEventsFile(AUDIT_EVENT_FILE)
	if err != nil {
		panic(err)
	}*/

	fmt.Println("==")

	fd, err := os.Open(AUDIT_PIPE)
	if err != nil {
		log.Printf("Err: %s", err)
	}
	defer fd.Close()

	//stat, err := fd.Stat()
	scanner := bufio.NewScanner(fd)

	// We use this to identify the last of the audit record
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
				if err := parseHeader32(buf, token); err != nil {
					fmt.Printf("Header parsing error: %+s", err)
				}

			case AUT_SUBJECT32:
				if err := parseSubject32(buf, token); err != nil {
					fmt.Printf("Subject parsing error: %+s", err)
				}

			case AUT_TEXT:
				if err := parseText(buf, token); err != nil {
					fmt.Printf("Text parsing error: %+s", err)
				}
			}
		}
		fmt.Printf("%+v", token)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseRecord(buf *bytes.Buffer) (uint32, byte, error) {
	var reclen uint32

	// Grab the first byte, determine the type
	eventType, err := buf.ReadByte()
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	// Let's wet the lips
	if debug {
		fmt.Printf("> Found new token type of: %s (%d)\n\n", TokenTypeDictionary[eventType], eventType)
	}

	switch eventType {
	case AUT_HEADER32,
		AUT_HEADER32_EX,
		AUT_HEADER64,
		AUT_HEADER64_EX:

		// Read the next few bytes of the header token
		// Get the record length
		reclen = ByteToInt32(buf.Bytes()[:sizeofUint32])

		break

	case AUT_OTHER_FILE32:
		if sec := readUint32(buf); sec < sizeofUint32 {
			return 0, eventType, nil
		}

		_ = readUint32(buf)
		filenamelen := readUint16(buf)
		reclen = uint32(sizeofChar + sizeofUint32 + sizeofUint32 + sizeofUint16 + filenamelen)
		break
	default:
		reclen = uint32(buf.Len())
	}

	return reclen, eventType, nil
}

// parseHeader32
func parseHeader32(buf *bytes.Buffer, tok *Token) error {
	h := Header32{}
	data := readNextBytes(buf, SizeHeader32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &h)
	if err != nil {
		return err
	}
	// Set the header in the token
	tok.Header32 = h
	return nil
}

// parseSubject32 parses the user/actor subject
func parseSubject32(buf *bytes.Buffer, tok *Token) error {
	subject := Subject32{}
	data := readNextBytes(buf, SizeSubject32)
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &subject)
	if err != nil {
		return err
	}
	// Set the header in the token
	tok.Subject32 = subject
	return nil
}

// parseText parses the text object, can be variable length
func parseText(buf *bytes.Buffer, tok *Token) error {
	tok.Text.Size = readUint16(buf)
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
