package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) SlashWorker(goCtx context.Context, msg *types.MsgSlashWorker) (*types.MsgSlashWorkerResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	worker, found := k.GetWorker(ctx, msg.Worker)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("worker not found")
	}

	if msg.SlashPercent == 0 || msg.SlashPercent > 50 {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("slash percent must be between 1 and 50")
	}

	slashAmount := worker.Stake * msg.SlashPercent / 100
	if slashAmount == 0 {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("slash amount is zero")
	}

	coins := sdk.NewCoins(sdk.NewCoin("stake", math.NewIntFromUint64(slashAmount)))
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return nil, err
	}

	worker.Stake -= slashAmount
	k.SetWorker(ctx, worker)

	return &types.MsgSlashWorkerResponse{}, nil
}
