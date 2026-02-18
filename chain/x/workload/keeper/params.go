package keeper

import (
	"context"

	"github.com/cosmos/cosmos-sdk/runtime"

	"chain/x/workload/types"
)

// GetParams get all parameters as types.Params
func (k Keeper) GetParams(ctx context.Context) (params types.Params) {
	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	bz := store.Get(types.ParamsKey)
	if bz == nil {
		return types.DefaultParams()
	}

	k.cdc.MustUnmarshal(bz, &params)
	return normalizeParams(params)
}

func normalizeParams(params types.Params) types.Params {
	defaults := types.DefaultParams()
	if params.WorkloadDenom == "" {
		params.WorkloadDenom = defaults.WorkloadDenom
	}
	if params.ChallengeWindowBlocks == 0 {
		params.ChallengeWindowBlocks = defaults.ChallengeWindowBlocks
	}
	if params.ChallengeDeposit == 0 {
		params.ChallengeDeposit = defaults.ChallengeDeposit
	}
	if params.ChallengerSlashPercent == 0 {
		params.ChallengerSlashPercent = defaults.ChallengerSlashPercent
	}
	if params.WorkerSlashPercentOnBadResult == 0 {
		params.WorkerSlashPercentOnBadResult = defaults.WorkerSlashPercentOnBadResult
	}
	return params
}

// SetParams set the params
func (k Keeper) SetParams(ctx context.Context, params types.Params) error {
	if err := params.Validate(); err != nil {
		return err
	}

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	bz, err := k.cdc.Marshal(&params)
	if err != nil {
		return err
	}
	store.Set(types.ParamsKey, bz)

	return nil
}
