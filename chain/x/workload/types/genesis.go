package types

import (
	"fmt"
)

// DefaultIndex is the default global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		TaskList:      []Task{},
		WorkerList:    []Worker{},
		UnbondingList: []Unbonding{},
		ChallengeList: []Challenge{},
		// this line is used by starport scaffolding # genesis/types/default
		Params: DefaultParams(),
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Check for duplicated ID in task
	taskIdMap := make(map[uint64]bool)
	taskCount := gs.GetTaskCount()
	for _, elem := range gs.TaskList {
		if _, ok := taskIdMap[elem.Id]; ok {
			return fmt.Errorf("duplicated id for task")
		}
		if elem.Id >= taskCount {
			return fmt.Errorf("task id should be lower or equal than the last id")
		}
		taskIdMap[elem.Id] = true
	}
	// Check for duplicated index in worker
	workerIndexMap := make(map[string]struct{})

	for _, elem := range gs.WorkerList {
		index := string(WorkerKey(elem.Creator))
		if _, ok := workerIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for worker")
		}
		workerIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in unbonding
	unbondingIndexMap := make(map[string]struct{})

	for _, elem := range gs.UnbondingList {
		index := string(UnbondingKey(elem.Creator))
		if _, ok := unbondingIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for unbonding")
		}
		unbondingIndexMap[index] = struct{}{}
	}
	// Check for duplicated ID in challenge
	challengeIDMap := make(map[uint64]bool)
	challengeCount := gs.GetChallengeCount()
	for _, elem := range gs.ChallengeList {
		if _, ok := challengeIDMap[elem.Id]; ok {
			return fmt.Errorf("duplicated id for challenge")
		}
		if elem.Id >= challengeCount {
			return fmt.Errorf("challenge id should be lower or equal than the last id")
		}
		challengeIDMap[elem.Id] = true
	}

	// this line is used by starport scaffolding # genesis/types/validate

	params := gs.Params
	if params.WorkloadDenom == "" {
		params = DefaultParams()
	}
	return params.Validate()
}
