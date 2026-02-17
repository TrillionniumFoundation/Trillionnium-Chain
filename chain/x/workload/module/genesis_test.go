package workload_test

import (
	"testing"

	keepertest "chain/testutil/keeper"
	"chain/testutil/nullify"
	"chain/x/workload/module"
	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		TaskList: []types.Task{
			{
				Id: 0,
			},
			{
				Id: 1,
			},
		},
		TaskCount: 2,
		WorkerList: []types.Worker{
			{
				Creator: "0",
			},
			{
				Creator: "1",
			},
		},
		UnbondingList: []types.Unbonding{
			{
				Creator: "0",
			},
			{
				Creator: "1",
			},
		},
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.WorkloadKeeper(t)
	workload.InitGenesis(ctx, k, genesisState)
	got := workload.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.TaskList, got.TaskList)
	require.Equal(t, genesisState.TaskCount, got.TaskCount)
	require.ElementsMatch(t, genesisState.WorkerList, got.WorkerList)
	require.ElementsMatch(t, genesisState.UnbondingList, got.UnbondingList)
	// this line is used by starport scaffolding # genesis/test/assert
}
