package main

/*
#include <bsm/libbsm.h>
#include <sys/types.h>
*/
import "C"

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mikemackintosh/go-auditx/lib/bsm"

	"bytes"
)

var debug bool = false

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

	fd, err := os.Open(bsm.AUDIT_PIPE)
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
		token := &bsm.Token{}

		for reclen = uint32(buf.Len()); reclen > 0; reclen, eventType, _ = parseRecord(buf) {
			switch eventType {
			case bsm.AUT_HEADER32:
				if err := bsm.ParseHeader32(buf, token); err != nil {
					fmt.Printf("Header parsing error: %+s", err)
				}

			case bsm.AUT_SUBJECT32:
				if err := bsm.ParseSubject32(buf, token); err != nil {
					fmt.Printf("Subject parsing error: %+s", err)
				}

			case bsm.AUT_TEXT:
				if err := bsm.ParseText(buf, token); err != nil {
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
		fmt.Printf("> Found new token type of: %s (%d)\n", bsm.TokenTypeDictionary[eventType], eventType)
	}

	switch eventType {
	case bsm.AUT_HEADER32,
		bsm.AUT_HEADER32_EX,
		bsm.AUT_HEADER64,
		bsm.AUT_HEADER64_EX:

		// Read the next few bytes of the header token
		// Get the record length
		reclen = ByteToInt32(buf.Bytes()[:sizeofUint32])

		break

	case bsm.AUT_OTHER_FILE32:
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
