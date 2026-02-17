package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) FinalizeUnbonding(goCtx context.Context, msg *types.MsgFinalizeUnbonding) (*types.MsgFinalizeUnbondingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	unbonding, found := k.GetUnbonding(ctx, msg.Creator)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("unbonding request not found")
	}

	if uint64(ctx.BlockHeight()) < unbonding.ReleaseHeight {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("unbonding cooldown not reached")
	}

	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	if unbonding.Amount > 0 {
		coins := sdk.NewCoins(sdk.NewCoin("stake", math.NewIntFromUint64(unbonding.Amount)))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, creator, coins); err != nil {
			return nil, err
		}
	}

	k.RemoveUnbonding(ctx, msg.Creator)

	return &types.MsgFinalizeUnbondingResponse{}, nil
}
