package keeper

import (
	"context"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const UnbondingPeriodBlocks uint64 = 100

func (k msgServer) RequestUnbonding(goCtx context.Context, msg *types.MsgRequestUnbonding) (*types.MsgRequestUnbondingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	worker, found := k.GetWorker(ctx, msg.Creator)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("worker not found")
	}

	if _, found := k.GetUnbonding(ctx, msg.Creator); found {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("unbonding already requested")
	}

	releaseHeight := uint64(ctx.BlockHeight()) + UnbondingPeriodBlocks
	k.SetUnbonding(ctx, types.Unbonding{
		Creator:       msg.Creator,
		ReleaseHeight: releaseHeight,
		Amount:        worker.Stake,
	})

	// worker exits active set immediately; stake can be withdrawn after cooldown
	k.RemoveWorker(ctx, msg.Creator)

	return &types.MsgRequestUnbondingResponse{}, nil
}
