package main

/*
#include <bsm/libbsm.h>
#include <sys/types.h>
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mikemackintosh/go-auditx/lib/bsm"
	"github.com/mikemackintosh/go-auditx/lib/config"

	"bytes"
)

func init() {
	flag.BoolVar(&config.Debug, "d", false, "Enable for debug")
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

	if config.Debug {
		fmt.Println("Waiting")
	}

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

			case
				bsm.AUT_SUBJECT32_EX,
				bsm.AUT_SUBJECT32:
				if err := bsm.ParseSubject32(buf, token); err != nil {
					fmt.Printf("Subject parsing error: %+s", err)
				}

			case bsm.AUT_ARG32:
				if err := bsm.ParseArg32(buf, token); err != nil {
					fmt.Printf("Arg32 parsing error: %+s", err)
				}

			case bsm.AUT_ARG64:
				if err := bsm.ParseArg64(buf, token); err != nil {
					fmt.Printf("Arg64 parsing error: %+s", err)
				}

			case bsm.AUT_SOCKET_EX,
				bsm.AUT_SOCKET:
				if err := bsm.ParseSocket(buf, token); err != nil {
					fmt.Printf("Socket parsing error: %+s", err)
				}

			case bsm.AUT_TEXT:
				if err := bsm.ParseText(buf, token); err != nil {
					fmt.Printf("Text parsing error: %+s", err)
				}

			case bsm.AUT_RETURN32:
				if err := bsm.ParseReturn(buf, token); err != nil {
					fmt.Printf("Return parsing error: %+s", err)
				}

			case bsm.AUT_TRAILER:
				if err := bsm.ParseTrailer(buf, token); err != nil {
					fmt.Printf("Trailer parsing error: %+s", err)
				}
			}
		}

		encoded, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Printf("%s\n", encoded)

		/*e2, err := xml.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Printf("%s\n", e2)*/
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseRecord(buf *bytes.Buffer) (uint32, byte, error) {
	var reclen uint32
	var eventType byte

	if buf.Len() == 0 {
		return 0, eventType, fmt.Errorf("Waiting for event record.")
	}

	// Grab the first byte, determine the type
	eventType, err := buf.ReadByte()
	if err != nil {
		fmt.Printf("> Error: %s", err)
	}

	// Let's wet the lips
	if config.Debug {
		fmt.Printf("> Found new token type of: %s (%d)\n", bsm.TokenTypeDictionary[eventType], eventType)
	}

	switch eventType {
	case bsm.AUT_HEADER32,
		bsm.AUT_HEADER32_EX,
		bsm.AUT_HEADER64,
		bsm.AUT_HEADER64_EX:

		// Read the next few bytes of the header token
		// Get the record length
		reclen = bsm.ByteToInt32(buf.Bytes()[:bsm.SizeofUint32])

		break

	case bsm.AUT_OTHER_FILE32:
		if sec := bsm.ReadUint32(buf); sec < bsm.SizeofUint32 {
			return 0, eventType, nil
		}

		_ = bsm.ReadUint32(buf)
		filenamelen := bsm.ReadUint16(buf)
		reclen = uint32(bsm.SizeofChar + bsm.SizeofUint32 + bsm.SizeofUint32 + bsm.SizeofUint16 + filenamelen)
		break
	default:
		reclen = uint32(buf.Len())
	}

	return reclen, eventType, nil
}
