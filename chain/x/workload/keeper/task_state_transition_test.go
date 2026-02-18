package keeper

import (
	"testing"

	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

func TestEnsureTaskTransition(t *testing.T) {
	require.NoError(t, ensureTaskTransition(types.TaskStatusOpen, types.TaskStatusAssigned))
	require.NoError(t, ensureTaskTransition(types.TaskStatusAssigned, types.TaskStatusCommitted))
	require.NoError(t, ensureTaskTransition(types.TaskStatusCommitted, types.TaskStatusRevealed))
	require.NoError(t, ensureTaskTransition(types.TaskStatusRevealed, types.TaskStatusCompleted))
	require.NoError(t, ensureTaskTransition(types.TaskStatusChallenged, types.TaskStatusSlashed))

	require.NoError(t, ensureTaskTransition(types.TaskStatusOpen, types.TaskStatusCompleted))
	require.Error(t, ensureTaskTransition(types.TaskStatusCompleted, types.TaskStatusAssigned))
}
