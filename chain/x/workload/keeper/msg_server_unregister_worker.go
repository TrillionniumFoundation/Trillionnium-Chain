package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) UnregisterWorker(goCtx context.Context, msg *types.MsgUnregisterWorker) (*types.MsgUnregisterWorkerResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	worker, found := k.GetWorker(ctx, msg.Creator)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("worker not found")
	}

	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	if worker.Stake > 0 {
		coins := sdk.NewCoins(sdk.NewCoin("stake", math.NewIntFromUint64(worker.Stake)))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, creator, coins); err != nil {
			return nil, err
		}
	}

	k.RemoveWorker(ctx, msg.Creator)

	return &types.MsgUnregisterWorkerResponse{}, nil
}
