package keeper

import (
	"context"
	"fmt"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateTask(goCtx context.Context, msg *types.MsgCreateTask) (*types.MsgCreateTaskResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	denom := k.workloadDenom(ctx)

	// 1. Convert bounty to TRNM denomination coin
	bountyCoin := sdk.NewCoin(denom, math.NewIntFromUint64(msg.Bounty))
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
		Status:     types.TaskStatusOpen,
		Worker:     "",
		ResultHash: "",
	}

	id := k.AppendTask(
		ctx,
		task,
	)

	emitFundFlowEvent(ctx, id, msg.Creator, types.ModuleName, msg.Bounty, denom, "bounty_lock")

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_create_task",
			sdk.NewAttribute("task_id", strconv.FormatUint(id, 10)),
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("bounty", strconv.FormatUint(msg.Bounty, 10)),
			sdk.NewAttribute("denom", denom),
		),
	)

	return &types.MsgCreateTaskResponse{
		Id: id,
	}, nil
}

func (k msgServer) UpdateTask(goCtx context.Context, msg *types.MsgUpdateTask) (*types.MsgUpdateTaskResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_deprecated_path",
			sdk.NewAttribute("method", "UpdateTask"),
			sdk.NewAttribute("message", "update-task is deprecated, use submit-result/challenge-result/resolve-challenge flow"),
		),
	)

	denom := k.workloadDenom(ctx)

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

	burned := uint64(0)
	// 3. Settlement Logic (TRNM policy)
	// If status is changing to COMPLETED (2), burn 100% of escrowed task fee.
	if msg.Status == 2 {
		bountyCoin := sdk.NewCoin(denom, math.NewIntFromUint64(val.Bounty))
		coins := sdk.NewCoins(bountyCoin)

		// Burn from module account (100% task fee burn policy)
		err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins)
		if err != nil {
			return nil, err
		}

		burned = val.Bounty
		emitFundFlowEvent(ctx, msg.Id, types.ModuleName, "burn", burned, denom, "task_burn")
		// Track who submitted the final result
		val.Worker = msg.Creator
	}

	// Update Fields
	val.IpfsHash = msg.IpfsHash
	val.Status = msg.Status
	val.ResultHash = msg.ResultHash

	k.SetTask(ctx, val)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_update_task",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.Id, 10)),
			sdk.NewAttribute("status", strconv.FormatUint(msg.Status, 10)),
			sdk.NewAttribute("worker", val.Worker),
			sdk.NewAttribute("burned", strconv.FormatUint(burned, 10)),
			sdk.NewAttribute("denom", denom),
		),
	)

	return &types.MsgUpdateTaskResponse{}, nil
}

func (k msgServer) DeleteTask(goCtx context.Context, msg *types.MsgDeleteTask) (*types.MsgDeleteTaskResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

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
