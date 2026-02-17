package types

const (
	// ModuleName defines the module name
	ModuleName = "compute"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_compute"
)

var (
	ParamsKey = []byte("p_compute")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
