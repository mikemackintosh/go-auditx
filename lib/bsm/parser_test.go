package bsm

import (
	"bytes"
	"testing"
)

func TestMain(t *testing.T) {

}

var bufferSeed = []byte{1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19}

var byteBuffer = bytes.NewBuffer(bufferSeed)

var charTest = []struct {
	byteBuffer *bytes.Buffer
	expected   []byte
}{
	{byteBuffer, []byte{1}},
}

func TestReadChar(t *testing.T) {
	for i, tt := range charTest {
		actual := ReadChar(byteBuffer, 1)
		if actual[0] != tt.expected[0] {
			t.Errorf("ReadChar(%d): expected %v, actual %v", i, tt.expected, actual)
		}
	}
}

var ntohTest = []struct {
	byteBuffer *bytes.Buffer
	expected   []byte
}{
	{byteBuffer, []byte{2, 3, 4, 5}},
}

func TestReadNtoh(t *testing.T) {
	for i, tt := range ntohTest {
		actual := ReadNtoh(byteBuffer, 4)
		if string(actual) != string(tt.expected) {
			t.Errorf("readNtoh(%d): expected %v, actual %v", i, tt.expected, actual)
		}
	}
}

var uint16Test = []struct {
	byteBuffer *bytes.Buffer
	expected   uint16
}{
	{byteBuffer, 1543}, // []byte{6,7}
}

func TestReadUint16(t *testing.T) {
	for i, tt := range uint16Test {
		actual := ReadUint16(byteBuffer)
		if actual != tt.expected {
			t.Errorf("readUint16(%d): expected %v, actual %v", i, tt.expected, actual)
		}
	}
}

var uint32Test = []struct {
	byteBuffer *bytes.Buffer
	expected   uint32
}{
	{byteBuffer, 134810123}, // []byte{8, 9, 10, 11}
}

func TestReadUint32(t *testing.T) {
	for i, tt := range uint32Test {
		actual := ReadUint32(byteBuffer)
		if actual != tt.expected {
			t.Errorf("readUint32(%d): expected %v, actual %v", i, tt.expected, actual)
		}
	}
}

var uint64Test = []struct {
	byteBuffer *bytes.Buffer
	expected   uint64
}{
	{byteBuffer, 868365761009226259}, // []byte{8, 9, 10, 11}
}

func TestReadUint64(t *testing.T) {
	for i, tt := range uint64Test {
		actual := ReadUint64(byteBuffer)
		if actual != tt.expected {
			t.Errorf("readUint64(%d): expected %v, actual %v", i, tt.expected, actual)
		}
	}
}
