package types

const (
	// ModuleName defines the module name
	ModuleName = "workload"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_workload"
)

var (
	ParamsKey = []byte("p_workload")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}

const (
	TaskKey           = "Task/value/"
	TaskCountKey      = "Task/count/"
	ChallengeKey      = "Challenge/value/"
	ChallengeCountKey = "Challenge/count/"
)
