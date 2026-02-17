package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const MinWorkerStake uint64 = 100000

func (k msgServer) RegisterWorker(goCtx context.Context, msg *types.MsgRegisterWorker) (*types.MsgRegisterWorkerResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, found := k.GetWorker(ctx, msg.Creator); found {
		return nil, sdkerrors.ErrUnauthorized.Wrap("worker already registered")
	}

	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	stakeCoin := sdk.NewCoin("stake", math.NewIntFromUint64(MinWorkerStake))
	stakeCoins := sdk.NewCoins(stakeCoin)

	// lock worker stake in module account
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, creator, types.ModuleName, stakeCoins); err != nil {
		return nil, err
	}

	k.SetWorker(ctx, types.Worker{
		Creator:  msg.Creator,
		NodeId:   msg.NodeId,
		IpfsAddr: msg.IpfsAddr,
		Stake:    MinWorkerStake,
	})

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_register_worker",
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("stake", strconv.FormatUint(MinWorkerStake, 10)),
		),
	)

	return &types.MsgRegisterWorkerResponse{}, nil
}
