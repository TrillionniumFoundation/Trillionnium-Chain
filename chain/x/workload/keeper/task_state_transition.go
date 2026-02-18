package keeper

import (
	"fmt"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
)

var allowedTaskTransitions = map[uint64]map[uint64]bool{
	types.TaskStatusOpen: {
		types.TaskStatusAssigned: true,
		types.TaskStatusRevealed: true, // legacy submit_result path
		types.TaskStatusCompleted: true, // privileged complete path from x/compute
	},
	types.TaskStatusAssigned: {
		types.TaskStatusCommitted: true,
	},
	types.TaskStatusCommitted: {
		types.TaskStatusRevealed: true,
		types.TaskStatusOpen:     true, // expired commit recovery
	},
	types.TaskStatusRevealed: {
		types.TaskStatusChallenged: true,
		types.TaskStatusCompleted:  true, // auto finalize
	},
	types.TaskStatusChallenged: {
		types.TaskStatusCompleted: true,
		types.TaskStatusSlashed:   true,
	},
}

func ensureTaskStatus(task types.Task, expected uint64, msg string) error {
	if task.Status != expected {
		if msg == "" {
			msg = fmt.Sprintf("invalid task status: expected=%d got=%d", expected, task.Status)
		}
		return errorsmod.Wrap(types.ErrInvalidTaskStateTransition, msg)
	}
	return nil
}

func ensureTaskTransition(from, to uint64) error {
	if allowedTaskTransitions[from][to] {
		return nil
	}
	return errorsmod.Wrapf(types.ErrInvalidTaskStateTransition, "invalid task status transition: %d -> %d", from, to)
}
