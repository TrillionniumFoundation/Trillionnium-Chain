package workload

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"chain/x/workload/keeper"
	"chain/x/workload/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the task
	for _, elem := range genState.TaskList {
		k.SetTask(ctx, elem)
	}

	// Set task count
	k.SetTaskCount(ctx, genState.TaskCount)
	// Set all the worker
	for _, elem := range genState.WorkerList {
		k.SetWorker(ctx, elem)
	}
	// this line is used by starport scaffolding # genesis/module/init
	k.SetParams(ctx, genState.Params)
}

// ExportGenesis returns the module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.TaskList = k.GetAllTask(ctx)
	genesis.TaskCount = k.GetTaskCount(ctx)
	genesis.WorkerList = k.GetAllWorker(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
