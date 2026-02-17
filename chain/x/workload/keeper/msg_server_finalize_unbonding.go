package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) FinalizeUnbonding(goCtx context.Context, msg *types.MsgFinalizeUnbonding) (*types.MsgFinalizeUnbondingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	unbonding, found := k.GetUnbonding(ctx, msg.Creator)
	if !found {
		return nil, types.ErrUnbondingNotFound
	}

	if ctx.BlockHeight() < 0 {
		return nil, types.ErrUnbondingCooldownNotReached
	}
	if uint64(ctx.BlockHeight()) < unbonding.ReleaseHeight {
		return nil, types.ErrUnbondingCooldownNotReached
	}

	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	denom := k.workloadDenom(ctx)
	if err := sdk.ValidateDenom(denom); err != nil {
		return nil, errorsmod.Wrapf(types.ErrInvalidWorkloadDenom, "stored denom %q is invalid: %v", denom, err)
	}

	if unbonding.Amount > 0 {
		coins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(unbonding.Amount)))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, creator, coins); err != nil {
			return nil, err
		}
	}

	k.RemoveUnbonding(ctx, msg.Creator)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_finalize_unbonding",
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("amount", strconv.FormatUint(unbonding.Amount, 10)),
			sdk.NewAttribute("denom", denom),
		),
	)

	return &types.MsgFinalizeUnbondingResponse{}, nil
}
