package keeper

import (
	"context"
	"os"
	"strconv"
	"strings"

	"chain/x/workload/types"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func extractTraceID(memo string) string {
	if memo == "" {
		return ""
	}
	for _, tok := range strings.Fields(memo) {
		if strings.HasPrefix(tok, "trace_id=") {
			return strings.TrimPrefix(tok, "trace_id=")
		}
	}
	return ""
}

func emitLegacySubmitObserveEvent(ctx sdk.Context, msg *types.MsgSubmitResult, result, reason string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_legacy_submit_observe",
			sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("height", strconv.FormatInt(ctx.BlockHeight(), 10)),
			sdk.NewAttribute("result", result),
			sdk.NewAttribute("reason", reason),
		),
	)
}

func (k msgServer) SubmitResult(goCtx context.Context, msg *types.MsgSubmitResult) (*types.MsgSubmitResultResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	params := k.GetParams(ctx)
	if !params.AllowLegacySubmitResult {
		emitLegacySubmitObserveEvent(ctx, msg, "rejected", "legacy_disabled")
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "legacy submit_result is disabled; use commit_result + reveal_result")
	}

	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if err := ensureTaskStatus(task, types.TaskStatusOpen, "task is not open"); err != nil {
		return nil, err
	}
	if err := ensureTaskTransition(task.Status, types.TaskStatusRevealed); err != nil {
		return nil, err
	}

	task.Worker = msg.Creator
	task.ResultHash = msg.ResultHash
	task.Status = types.TaskStatusRevealed
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
	emitLegacySubmitObserveEvent(ctx, msg, "accepted", "legacy_enabled")

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
	if err := ensureTaskStatus(task, types.TaskStatusRevealed, "task is not in revealed status"); err != nil {
		return nil, err
	}
	if task.ChallengeDeadlineHeight == 0 {
		return nil, errorsmod.Wrap(types.ErrChallengeWindowNotStarted, "challenge window not started")
	}
	if uint64(ctx.BlockHeight()) > task.ChallengeDeadlineHeight {
		return nil, errorsmod.Wrap(types.ErrChallengeWindowExpired, "challenge window expired")
	}

	params := k.GetParams(ctx)
	challengerAddr, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, err
	}
	if params.ChallengeDeposit > 0 {
		denom := k.workloadDenom(ctx)
		depositCoins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(params.ChallengeDeposit)))
		if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, challengerAddr, types.ModuleName, depositCoins); err != nil {
			return nil, err
		}
		emitFundFlowEvent(ctx, task.Id, msg.Creator, types.ModuleName, params.ChallengeDeposit, denom, "challenge_deposit")
	}

	challenge := types.Challenge{
		TaskId:        task.Id,
		Challenger:    msg.Creator,
		Worker:        task.Worker,
		Status:        types.ChallengeStatusOpen,
		Deposit:       params.ChallengeDeposit,
		Reason:        msg.Reason,
		EvidenceUri:   msg.EvidenceUri,
		CreatedHeight: uint64(ctx.BlockHeight()),
	}
	challengeID := k.AppendChallenge(ctx, challenge)

	if err := ensureTaskTransition(task.Status, types.TaskStatusChallenged); err != nil {
		return nil, err
	}
	task.Status = types.TaskStatusChallenged
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

	task, found := k.GetTask(ctx, msg.TaskId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "task %d not found", msg.TaskId)
	}
	if err := ensureTaskStatus(task, types.TaskStatusChallenged, "task is not challenged"); err != nil {
		return nil, err
	}

	challenge, found := k.GetChallenge(ctx, task.ChallengeId)
	if !found {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "challenge %d not found", task.ChallengeId)
	}

	// DEV escape hatch for local chain automation only (default OFF).
	// Enable explicitly with TRNM_ENABLE_DEV_RESOLVE=1 on the node process.
	isDevLocalResolve := os.Getenv("TRNM_ENABLE_DEV_RESOLVE") == "1" &&
		ctx.ChainID() == "trillionnium" &&
		msg.Creator == challenge.Challenger
	if msg.Creator != k.authority && !isDevLocalResolve {
		return nil, errorsmod.Wrap(types.ErrUnauthorizedSlash, "only authority can resolve challenge")
	}

	params := k.GetParams(ctx)
	challengerAddr, err := sdk.AccAddressFromBech32(challenge.Challenger)
	if err != nil {
		return nil, err
	}

	resolveOut, err := k.disputeResolver.Resolve(ctx, types.DisputeResolveInput{
		Task:               task,
		Challenge:          challenge,
		ChallengeSucceeded: msg.ChallengeSucceeded,
		FinalResultHash:    msg.FinalResultHash,
		Memo:               msg.Memo,
	})
	if err != nil {
		return nil, err
	}

	challenge.Status = resolveOut.ChallengeStatus
	challenge.ResolvedHeight = uint64(ctx.BlockHeight())

	if err := ensureTaskTransition(task.Status, resolveOut.TaskStatus); err != nil {
		return nil, err
	}

	if resolveOut.TaskStatus == types.TaskStatusSlashed {
		task.Status = resolveOut.TaskStatus
		if task.Worker != "" {
			_, err := k.SlashWorker(goCtx, &types.MsgSlashWorker{
				Creator:      k.authority,
				Worker:       task.Worker,
				SlashPercent: params.WorkerSlashPercentOnBadResult,
			})
			if err != nil {
				return nil, err
			}
		}
		if challenge.Deposit > 0 {
			denom := k.workloadDenom(ctx)
			depositCoins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(challenge.Deposit)))
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, challengerAddr, depositCoins); err != nil {
				return nil, err
			}
			emitFundFlowEvent(ctx, task.Id, types.ModuleName, challenge.Challenger, challenge.Deposit, denom, "challenge_refund")
		}
		task.ResultHash = resolveOut.FinalResultHash
		k.SetTask(ctx, task)
		k.SetChallenge(ctx, challenge)
	} else {
		if challenge.Deposit > 0 {
			denom := k.workloadDenom(ctx)
			penalty := challenge.Deposit * params.ChallengerSlashPercent / 100
			refund := challenge.Deposit - penalty

			if penalty > 0 {
				penaltyCoins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(penalty)))
				if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, penaltyCoins); err != nil {
					return nil, err
				}
				emitFundFlowEvent(ctx, task.Id, types.ModuleName, "burn", penalty, denom, "challenge_burn")
			}
			if refund > 0 {
				refundCoins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(refund)))
				if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, challengerAddr, refundCoins); err != nil {
					return nil, err
				}
				emitFundFlowEvent(ctx, task.Id, types.ModuleName, challenge.Challenger, refund, denom, "challenge_refund")
			}
		}

		if err := k.CompleteTask(ctx, task.Id, task.Worker, resolveOut.FinalResultHash); err != nil {
			return nil, err
		}
		k.SetChallenge(ctx, challenge)
	}
	attrs := []sdk.Attribute{
		sdk.NewAttribute("task_id", strconv.FormatUint(msg.TaskId, 10)),
		sdk.NewAttribute("challenge_succeeded", strconv.FormatBool(msg.ChallengeSucceeded)),
	}
	if traceID := extractTraceID(msg.Memo); traceID != "" {
		attrs = append(attrs, sdk.NewAttribute("trace_id", traceID))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent("workload_resolve_challenge", attrs...))

	return &types.MsgResolveChallengeResponse{}, nil
}
