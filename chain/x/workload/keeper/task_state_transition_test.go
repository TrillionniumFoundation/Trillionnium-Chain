package keeper

import (
	"testing"

	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

func TestEnsureTaskTransition(t *testing.T) {
	require.NoError(t, ensureTaskTransition(types.TaskStatusOpen, types.TaskStatusAssigned))
	require.NoError(t, ensureTaskTransition(types.TaskStatusAssigned, types.TaskStatusResultSubmitted))
	require.NoError(t, ensureTaskTransition(types.TaskStatusResultSubmitted, types.TaskStatusCompleted))
	require.NoError(t, ensureTaskTransition(types.TaskStatusChallenged, types.TaskStatusSlashed))

	require.Error(t, ensureTaskTransition(types.TaskStatusOpen, types.TaskStatusCompleted))
	require.Error(t, ensureTaskTransition(types.TaskStatusCompleted, types.TaskStatusAssigned))
}
