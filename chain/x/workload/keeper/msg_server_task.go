package keeper

import (
	"context"
	"fmt"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateTask(goCtx context.Context, msg *types.MsgCreateTask) (*types.MsgCreateTaskResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Convert Bounty to Coins (Assume denom is "utrnm")
	// For simplicity, we hardcode denom here. In production, pass it in params.
	bountyCoin := sdk.NewCoin("token", math.NewIntFromUint64(msg.Bounty))
	coins := sdk.NewCoins(bountyCoin)

	// 2. Get Creator Address
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}

	// 3. Transfer Bounty from Creator to Module Account
	// This locks the funds until task completion
	err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, creator, types.ModuleName, coins)
	if err != nil {
		return nil, err
	}

	var task = types.Task{
		Creator:    msg.Creator,
		IpfsHash:   msg.IpfsHash,
		Bounty:     msg.Bounty,
		Status:     0, // 0 = OPEN
		Worker:     "",
		ResultHash: "",
	}

	id := k.AppendTask(
		ctx,
		task,
	)

	return &types.MsgCreateTaskResponse{
		Id: id,
	}, nil
}

func (k msgServer) UpdateTask(goCtx context.Context, msg *types.MsgUpdateTask) (*types.MsgUpdateTaskResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Get Existing Task
	val, found := k.GetTask(ctx, msg.Id)
	if !found {
		return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, fmt.Sprintf("key %d doesn't exist", msg.Id))
	}

	// 2. Check Logic
	// Only the assigned Worker can submit result (simplified: open submission for now)
	// If task is already completed, reject.
	if val.Status == 2 { // 2 = COMPLETED
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task already completed")
	}

	// 3. Payout Logic
	// If status is changing to COMPLETED (2), pay the worker
	if msg.Status == 2 {
		workerAddr, err := sdk.AccAddressFromBech32(msg.Creator) // The msg sender is the worker
		if err != nil {
			return nil, err
		}

		bountyCoin := sdk.NewCoin("token", math.NewIntFromUint64(val.Bounty))
		coins := sdk.NewCoins(bountyCoin)

		// Transfer from Module -> Worker
		err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, workerAddr, coins)
		if err != nil {
			return nil, err
		}
		
		// Update Worker field to the sender
		val.Worker = msg.Creator
	}

	// Update Fields
	val.IpfsHash = msg.IpfsHash
	val.Status = msg.Status
	val.ResultHash = msg.ResultHash

	k.SetTask(ctx, val)

	return &types.MsgUpdateTaskResponse{}, nil
}

func (k msgServer) DeleteTask(goCtx context.Context, msg *types.MsgDeleteTask) (*types.MsgDeleteTaskResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Checks that the element exists
	val, found := k.GetTask(ctx, msg.Id)
	if !found {
		return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, fmt.Sprintf("key %d doesn't exist", msg.Id))
	}

	// Checks if the msg creator is the same as the current owner
	if msg.Creator != val.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "incorrect owner")
	}

	k.RemoveTask(ctx, msg.Id)

	return &types.MsgDeleteTaskResponse{}, nil
}
