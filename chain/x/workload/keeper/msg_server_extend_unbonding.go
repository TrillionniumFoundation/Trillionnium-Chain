package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const MaxExtraUnbondingBlocks uint64 = 10000

func (k msgServer) ExtendUnbonding(goCtx context.Context, msg *types.MsgExtendUnbonding) (*types.MsgExtendUnbondingResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// governance-only control: only authority can extend cooldown windows
	if msg.Creator != k.GetAuthority() {
		return nil, types.ErrUnauthorizedUnbondingExtend
	}

	if msg.ExtraBlocks == 0 || msg.ExtraBlocks > MaxExtraUnbondingBlocks {
		return nil, types.ErrInvalidExtraBlocks
	}

	if _, err := sdk.AccAddressFromBech32(msg.Worker); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid worker address: %v", err)
	}

	unbonding, found := k.GetUnbonding(ctx, msg.Worker)
	if !found {
		return nil, types.ErrUnbondingNotFound
	}

	if unbonding.ReleaseHeight > ^uint64(0)-msg.ExtraBlocks {
		return nil, types.ErrInvalidExtraBlocks
	}

	unbonding.ReleaseHeight += msg.ExtraBlocks
	k.SetUnbonding(ctx, unbonding)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_extend_unbonding",
			sdk.NewAttribute("worker", msg.Worker),
			sdk.NewAttribute("extra_blocks", strconv.FormatUint(msg.ExtraBlocks, 10)),
			sdk.NewAttribute("new_release_height", strconv.FormatUint(unbonding.ReleaseHeight, 10)),
		),
	)

	return &types.MsgExtendUnbondingResponse{}, nil
}
