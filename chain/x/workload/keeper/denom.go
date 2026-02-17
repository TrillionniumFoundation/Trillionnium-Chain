package keeper

import "context"

func (k Keeper) workloadDenom(ctx context.Context) string {
	params := k.GetParams(ctx)
	if params.WorkloadDenom == "" {
		return "utrnm"
	}
	return params.WorkloadDenom
}
