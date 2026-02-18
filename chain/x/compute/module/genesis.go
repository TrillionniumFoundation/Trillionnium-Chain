package compute

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"chain/x/compute/keeper"
	"chain/x/compute/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// this line is used by starport scaffolding # genesis/module/init
	k.SetParams(ctx, genState.Params)
	
	// Set all the job
	for _, elem := range genState.JobList {
		k.SetJob(ctx, elem)
	}

	// Set job count
	k.SetJobCount(ctx, genState.JobCount)
}

// ExportGenesis returns the module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.JobList = k.GetAllJob(ctx)
	genesis.JobCount = k.GetJobCount(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
