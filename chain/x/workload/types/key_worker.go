package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// WorkerKeyPrefix is the prefix to retrieve all Worker
	WorkerKeyPrefix = "Worker/value/"
)

// WorkerKey returns the store key to retrieve a Worker from the index fields
func WorkerKey(
	creator string,
) []byte {
	var key []byte

	creatorBytes := []byte(creator)
	key = append(key, creatorBytes...)
	key = append(key, []byte("/")...)

	return key
}
