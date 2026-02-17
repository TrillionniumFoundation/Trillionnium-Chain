package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const UnbondingPeriodBlocks uint64 = 100
const maxSafeUnbondingStartHeight int64 = int64(^uint64(0)>>1) - int64(UnbondingPeriodBlocks)

func (k msgServer) RequestUnbonding(goCtx context.Context, msg *types.MsgRequestUnbonding) (*types.MsgRequestUnbondingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	worker, found := k.GetWorker(ctx, msg.Creator)
	if !found {
		return nil, types.ErrWorkerNotFound
	}

	if _, found := k.GetUnbonding(ctx, msg.Creator); found {
		return nil, types.ErrUnbondingAlreadyRequested
	}

	if ctx.BlockHeight() < 0 || ctx.BlockHeight() > maxSafeUnbondingStartHeight {
		return nil, types.ErrInvalidBlockHeight
	}

	releaseHeight := uint64(ctx.BlockHeight()) + UnbondingPeriodBlocks
	k.SetUnbonding(ctx, types.Unbonding{
		Creator:       msg.Creator,
		ReleaseHeight: releaseHeight,
		Amount:        worker.Stake,
	})

	// worker exits active set immediately; stake can be withdrawn after cooldown
	k.RemoveWorker(ctx, msg.Creator)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_request_unbonding",
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("release_height", strconv.FormatUint(releaseHeight, 10)),
			sdk.NewAttribute("amount", strconv.FormatUint(worker.Stake, 10)),
		),
	)

	return &types.MsgRequestUnbondingResponse{}, nil
}
