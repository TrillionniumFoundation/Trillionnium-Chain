package keeper

import (
	"testing"

	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

func TestTaskStateTransitionMatrix(t *testing.T) {
	states := []uint64{
		types.TaskStatusOpen,
		types.TaskStatusAssigned,
		types.TaskStatusCommitted,
		types.TaskStatusRevealed,
		types.TaskStatusChallenged,
		types.TaskStatusCompleted,
		types.TaskStatusSlashed,
	}

	allowed := map[[2]uint64]bool{
		{types.TaskStatusOpen, types.TaskStatusAssigned}: true,
		{types.TaskStatusOpen, types.TaskStatusRevealed}: true, // legacy submit_result
		{types.TaskStatusOpen, types.TaskStatusCompleted}: true, // privileged complete path
		{types.TaskStatusAssigned, types.TaskStatusCommitted}: true,
		{types.TaskStatusCommitted, types.TaskStatusRevealed}: true,
		{types.TaskStatusCommitted, types.TaskStatusOpen}:     true, // commit timeout recovery
		{types.TaskStatusRevealed, types.TaskStatusChallenged}: true,
		{types.TaskStatusRevealed, types.TaskStatusCompleted}:  true,
		{types.TaskStatusChallenged, types.TaskStatusCompleted}: true,
		{types.TaskStatusChallenged, types.TaskStatusSlashed}:   true,
	}

	for _, from := range states {
		for _, to := range states {
			if from == to {
				continue
			}
			err := ensureTaskTransition(from, to)
			if allowed[[2]uint64{from, to}] {
				require.NoError(t, err, "expected transition %d -> %d to be allowed", from, to)
			} else {
				require.ErrorIs(t, err, types.ErrInvalidTaskStateTransition, "expected transition %d -> %d to be rejected", from, to)
			}
		}
	}
}
