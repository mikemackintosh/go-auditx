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

const SizeofChar = C.sizeof_char
const SizeofUint16 = C.sizeof_u_int16_t
const SizeofUint32 = C.sizeof_u_int32_t
const SizeofUint64 = C.sizeof_u_int64_t

func readNextBytes(buffer *bytes.Buffer, size int) []byte {
	bytes := make([]byte, size)

	_, err := buffer.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}

func ReadChar(buf *bytes.Buffer, size int) []byte {
	return buf.Next(size)
}

func ReadNtoh(buf *bytes.Buffer, size int) []byte {
	return buf.Next(size)
}

func ReadUint16(buf *bytes.Buffer) uint16 {
	return binary.BigEndian.Uint16(buf.Next(SizeofUint16))
}

func ReadUint32(buf *bytes.Buffer) uint32 {
	return binary.BigEndian.Uint32(buf.Next(SizeofUint32))
}

func ReadUint64(buf *bytes.Buffer) uint64 {
	return binary.BigEndian.Uint64(buf.Next(SizeofUint64))
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
