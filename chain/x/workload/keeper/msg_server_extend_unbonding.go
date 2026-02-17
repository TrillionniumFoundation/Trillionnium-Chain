package keeper

import (
	"context"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const MaxExtraUnbondingBlocks uint64 = 10000

func (k msgServer) ExtendUnbonding(goCtx context.Context, msg *types.MsgExtendUnbonding) (*types.MsgExtendUnbondingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// governance-only control: only authority can extend cooldown windows
	if msg.Creator != k.GetAuthority() {
		return nil, sdkerrors.ErrUnauthorized.Wrap("only authority can extend unbonding")
	}

	if msg.ExtraBlocks == 0 {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("extraBlocks must be > 0")
	}
	if msg.ExtraBlocks > MaxExtraUnbondingBlocks {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("extraBlocks exceeds max extension limit")
	}

	unbonding, found := k.GetUnbonding(ctx, msg.Worker)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("unbonding request not found")
	}

	unbonding.ReleaseHeight += msg.ExtraBlocks
	k.SetUnbonding(ctx, unbonding)

	return &types.MsgExtendUnbondingResponse{}, nil
}
