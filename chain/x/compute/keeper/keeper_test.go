package keeper_test

import (
	"testing"

	"chain/x/compute/keeper"
	workloadkeeper "chain/x/workload/keeper"
	"github.com/stretchr/testify/require"
)

// TestComputeKeeperDependency verifies that x/compute can import x/workload/keeper
// This is a placeholder test for future integration.
func TestComputeKeeperDependency(t *testing.T) {
	// Verify we can reference the workload keeper type
	var _ *workloadkeeper.Keeper = nil
	
	// Verify we can reference the compute keeper type
	var _ *keeper.Keeper = nil

	// If we can compile this file, it means the dependencies are resolved.
	require.True(t, true)
}
