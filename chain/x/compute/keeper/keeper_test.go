package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "chain/testutil/keeper"
	workloadtypes "chain/x/workload/types"
)

func TestComputeKeeperDependency(t *testing.T) {
	k, workloadK, ctx := keepertest.ComputeKeeperWithWorkload(t)

	// Set workload params via workload keeper
	defaultParams := workloadtypes.DefaultParams()
	// Let's modify a field if possible to ensure we are reading the same data,
	// but DefaultParams fields might be empty or basic.
	// Assuming Params has fields we can check.
	err := workloadK.SetParams(ctx, defaultParams)
	require.NoError(t, err)

	// Read workload params via compute keeper
	retrievedParams := k.GetWorkloadParams(ctx)

	// Verify they are the same
	require.Equal(t, defaultParams, retrievedParams)
}
