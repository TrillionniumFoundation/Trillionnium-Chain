package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const UnbondingPeriodBlocks uint64 = 100
const maxSafeUnbondingStartHeight int64 = int64(^uint64(0)>>1) - int64(UnbondingPeriodBlocks)

func (k msgServer) RequestUnbonding(goCtx context.Context, msg *types.MsgRequestUnbonding) (*types.MsgRequestUnbondingResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, err := sdk.AccAddressFromBech32(msg.Creator); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address: %v", err)
	}

	worker, found := k.GetWorker(ctx, msg.Creator)
	if !found {
		return nil, types.ErrWorkerNotFound
	}

	if worker.Stake == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "worker has no stake to unbond")
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
