package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const (
	taskStatusOpen            uint64 = 0
	taskStatusResultSubmitted uint64 = 1
	taskStatusCompleted       uint64 = 2
	taskStatusChallenged      uint64 = 3
)

func (k msgServer) SubmitResult(goCtx context.Context, msg *types.MsgSubmitResult) (*types.MsgSubmitResultResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if task.Status != taskStatusOpen {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task is not open")
	}

	params := k.GetParams(ctx)
	task.Worker = msg.Creator
	task.ResultHash = msg.ResultHash
	task.Status = taskStatusResultSubmitted
	task.ChallengeDeadlineHeight = uint64(ctx.BlockHeight()) + params.ChallengeWindowBlocks
	k.SetTask(ctx, task)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_submit_result",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("result_hash", msg.ResultHash),
			sdk.NewAttribute("challenge_deadline_height", strconv.FormatUint(task.ChallengeDeadlineHeight, 10)),
		),
	)

	return &types.MsgSubmitResultResponse{}, nil
}

func (k msgServer) ChallengeResult(goCtx context.Context, msg *types.MsgChallengeResult) (*types.MsgChallengeResultResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if task.Status != taskStatusResultSubmitted {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task is not in result-submitted status")
	}
	if uint64(ctx.BlockHeight()) > task.ChallengeDeadlineHeight {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "challenge window expired")
	}

	params := k.GetParams(ctx)
	challengerAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}
	if params.ChallengeDeposit > 0 {
		depositCoins := sdk.NewCoins(sdk.NewCoin(k.workloadDenom(ctx), math.NewIntFromUint64(params.ChallengeDeposit)))
		if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, challengerAddr, types.ModuleName, depositCoins); err != nil {
			return nil, err
		}
	}

	challenge := types.Challenge{
		TaskId:        task.Id,
		Challenger:    msg.Creator,
		Worker:        task.Worker,
		Status:        0,
		Deposit:       params.ChallengeDeposit,
		Reason:        msg.Reason,
		EvidenceUri:   msg.EvidenceUri,
		CreatedHeight: uint64(ctx.BlockHeight()),
	}
	challengeID := k.AppendChallenge(ctx, challenge)

	task.Status = taskStatusChallenged
	task.Challenger = msg.Creator
	task.ChallengeId = challengeID
	k.SetTask(ctx, task)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_challenge_result",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("challenger", msg.Creator),
		),
	)

	return &types.MsgChallengeResultResponse{}, nil
}

func (k msgServer) ResolveChallenge(goCtx context.Context, msg *types.MsgResolveChallenge) (*types.MsgResolveChallengeResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if msg.Creator != k.authority {
		return nil, errorsmod.Wrap(types.ErrUnauthorizedSlash, "only authority can resolve challenge")
	}

	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if task.Status != taskStatusChallenged {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task is not challenged")
	}

	challenge, found := k.GetChallenge(ctx, task.ChallengeId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "challenge %d not found", task.ChallengeId)
	}

	params := k.GetParams(ctx)
	challengerAddr, err := sdk.AccAddressFromBech32(challenge.Challenger)
	if err != nil {
		return nil, err
	}

	if msg.ChallengeSucceeded {
		task.Status = 4 // SLASHED
		challenge.Status = 1
		if task.Worker != "" {
			_, err := k.SlashWorker(goCtx, &types.MsgSlashWorker{
				Creator:      msg.Creator,
				Worker:       task.Worker,
				SlashPercent: params.WorkerSlashPercentOnBadResult,
			})
			if err != nil {
				return nil, err
			}
		}
		if challenge.Deposit > 0 {
			depositCoins := sdk.NewCoins(sdk.NewCoin(k.workloadDenom(ctx), math.NewIntFromUint64(challenge.Deposit)))
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, challengerAddr, depositCoins); err != nil {
				return nil, err
			}
		}
		if msg.FinalResultHash != "" {
			task.ResultHash = msg.FinalResultHash
		}
		challenge.ResolvedHeight = uint64(ctx.BlockHeight())
		k.SetChallenge(ctx, challenge)
		k.SetTask(ctx, task)
	} else {
		challenge.Status = 2
		if challenge.Deposit > 0 {
			penalty := challenge.Deposit * params.ChallengerSlashPercent / 100
			refund := challenge.Deposit - penalty

			if penalty > 0 {
				penaltyCoins := sdk.NewCoins(sdk.NewCoin(k.workloadDenom(ctx), math.NewIntFromUint64(penalty)))
				if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, penaltyCoins); err != nil {
					return nil, err
				}
			}
			if refund > 0 {
				refundCoins := sdk.NewCoins(sdk.NewCoin(k.workloadDenom(ctx), math.NewIntFromUint64(refund)))
				if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, challengerAddr, refundCoins); err != nil {
					return nil, err
				}
			}
		}

		finalHash := task.ResultHash
		if msg.FinalResultHash != "" {
			finalHash = msg.FinalResultHash
		}
		if err := k.CompleteTask(ctx, task.Id, task.Worker, finalHash); err != nil {
			return nil, err
		}
		challenge.ResolvedHeight = uint64(ctx.BlockHeight())
		k.SetChallenge(ctx, challenge)
	}
	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_resolve_challenge",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("challenge_succeeded", strconv.FormatBool(msg.ChallengeSucceeded)),
		),
	)

	return &types.MsgResolveChallengeResponse{}, nil
}
