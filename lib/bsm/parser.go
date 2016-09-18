package bsm

/*
#include <bsm/libbsm.h>
#include <sys/types.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"log"
)

const sizeofChar = C.sizeof_char
const sizeofUint16 = C.sizeof_u_int16_t
const sizeofUint32 = C.sizeof_u_int32_t
const sizeofUint64 = C.sizeof_u_int64_t

func readNextBytes(buffer *bytes.Buffer, size int) []byte {
	bytes := make([]byte, size)

	_, err := buffer.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}

func readChar(buf *bytes.Buffer, size int) []byte {
	return buf.Next(size)
}

func readNtoh(buf *bytes.Buffer, size int) []byte {
	return buf.Next(size)
}

func readUint16(buf *bytes.Buffer) uint16 {
	return binary.BigEndian.Uint16(buf.Next(sizeofUint16))
}

func readUint32(buf *bytes.Buffer) uint32 {
	return binary.BigEndian.Uint32(buf.Next(sizeofUint32))
}

func readUint64(buf *bytes.Buffer) uint64 {
	return binary.BigEndian.Uint64(buf.Next(sizeofUint64))
}
