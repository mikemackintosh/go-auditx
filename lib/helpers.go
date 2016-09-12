package auditx

import (
	"log"
	"os"
)

// Btoi will convert byte slices to integers
func Btoi(array []byte) uint64 {
	var out uint64
	l := len(array)
	for i, b := range array {
		shift := uint64((l - i - 1) * 8)
		out |= uint64(b) << shift
	}
	return out
}

// ReadNextBytes will take a file attribute
func ReadNextBytes(file *os.File, number int) []byte {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}
