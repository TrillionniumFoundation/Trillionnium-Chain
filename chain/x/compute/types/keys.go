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

const (
	// JobKey is the prefix to retrieve all Job
	JobKey = "Job/value/"
	// JobCountKey is the key to retrieve the Job count
	JobCountKey = "Job/count/"
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
