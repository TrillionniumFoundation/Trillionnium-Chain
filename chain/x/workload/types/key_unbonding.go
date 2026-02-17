package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// UnbondingKeyPrefix is the prefix to retrieve all Unbonding
	UnbondingKeyPrefix = "Unbonding/value/"
)

// UnbondingKey returns the store key to retrieve a Unbonding from the index fields
func UnbondingKey(
	creator string,
) []byte {
	var key []byte

	creatorBytes := []byte(creator)
	key = append(key, creatorBytes...)
	key = append(key, []byte("/")...)

	return key
}
