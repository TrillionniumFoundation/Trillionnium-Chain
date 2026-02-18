package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CommitResult(goCtx context.Context, msg *types.MsgCommitResult) (*types.MsgCommitResultResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}
	if msg.CommitHash == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "commit hash cannot be empty")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if err := ensureTaskStatus(task, types.TaskStatusAssigned, "task is not assigned"); err != nil {
		return nil, err
	}
	if task.Worker != msg.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "only assigned worker can commit")
	}
	if task.CommitHash != "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task already committed")
	}

	params := k.GetParams(ctx)
	task.Worker = msg.Creator
	task.CommitHash = msg.CommitHash
	task.CommitHeight = uint64(ctx.BlockHeight())
	task.RevealDeadlineHeight = uint64(ctx.BlockHeight()) + params.RevealWindowBlocks
	k.SetTask(ctx, task)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_commit_result",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("commit_hash", msg.CommitHash),
			sdk.NewAttribute("reveal_deadline_height", strconv.FormatUint(task.RevealDeadlineHeight, 10)),
		),
	)

	return &types.MsgCommitResultResponse{}, nil
}

func (k msgServer) RevealResult(goCtx context.Context, msg *types.MsgRevealResult) (*types.MsgRevealResultResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}
	if msg.ResultHash == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "result hash cannot be empty")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if err := ensureTaskStatus(task, types.TaskStatusAssigned, "task is not assigned for reveal"); err != nil {
		return nil, err
	}
	if task.Worker != msg.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "only committed worker can reveal")
	}
	if task.CommitHash == "" {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "missing commit hash")
	}
	if uint64(ctx.BlockHeight()) > task.RevealDeadlineHeight {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "reveal window expired")
	}

	expected := calculateCommitHash(msg.TaskId, msg.ResultHash, msg.RevealSalt, msg.Creator)
	if expected != task.CommitHash {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "reveal does not match commit hash")
	}

	params := k.GetParams(ctx)
	if err := ensureTaskTransition(task.Status, types.TaskStatusResultSubmitted); err != nil {
		return nil, err
	}
	task.ResultHash = msg.ResultHash
	task.ResultUri = msg.ResultUri
	task.Status = types.TaskStatusResultSubmitted
	task.ChallengeDeadlineHeight = uint64(ctx.BlockHeight()) + params.ChallengeWindowBlocks
	k.SetTask(ctx, task)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_reveal_result",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("result_hash", msg.ResultHash),
			sdk.NewAttribute("challenge_deadline_height", strconv.FormatUint(task.ChallengeDeadlineHeight, 10)),
		),
	)

	return &types.MsgRevealResultResponse{}, nil
}

func calculateCommitHash(taskID uint64, resultHash, revealSalt, worker string) string {
	payload := fmt.Sprintf("%d|%s|%s|%s", taskID, resultHash, revealSalt, worker)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}
