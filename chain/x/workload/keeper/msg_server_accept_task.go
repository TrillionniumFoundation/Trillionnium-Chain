package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) AcceptTask(goCtx context.Context, msg *types.MsgAcceptTask) (*types.MsgAcceptTaskResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if err := ensureTaskStatus(task, types.TaskStatusOpen, "task is not open"); err != nil {
		return nil, err
	}
	if task.Worker != "" && task.Worker != msg.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task already assigned")
	}

	if _, found := k.GetWorker(ctx, msg.Creator); !found {
		return nil, errorsmod.Wrap(types.ErrWorkerNotFound, "worker must be registered before accepting task")
	}

	if err := ensureTaskTransition(task.Status, types.TaskStatusAssigned); err != nil {
		return nil, err
	}
	task.Worker = msg.Creator
	task.Status = types.TaskStatusAssigned
	k.SetTask(ctx, task)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_accept_task",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
		),
	)

	return &types.MsgAcceptTaskResponse{}, nil
}
