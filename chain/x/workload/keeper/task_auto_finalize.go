package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AutoFinalizeSubmittedTasks finalizes tasks that passed challenge window without challenge.
func (k Keeper) AutoFinalizeSubmittedTasks(ctx context.Context) error {
	tasks := k.GetAllTask(ctx)
	currentHeight := uint64(0)
	sdkCtx, ok := ctx.(interface{ BlockHeight() int64 })
	if ok && sdkCtx.BlockHeight() > 0 {
		currentHeight = uint64(sdkCtx.BlockHeight())
	}

	for _, task := range tasks {
		if task.Status != types.TaskStatusResultSubmitted {
			continue
		}
		if currentHeight <= task.ChallengeDeadlineHeight {
			continue
		}
		if err := k.CompleteTask(ctx, task.Id, task.Worker, task.ResultHash); err != nil {
			return err
		}
	}

	return k.AutoRecoverExpiredCommits(ctx)
}

// AutoRecoverExpiredCommits clears stale commit state when reveal window expires.
func (k Keeper) AutoRecoverExpiredCommits(ctx context.Context) error {
	tasks := k.GetAllTask(ctx)
	sdkCtx, ok := ctx.(sdk.Context)
	if !ok {
		return nil
	}
	currentHeight := uint64(0)
	if sdkCtx.BlockHeight() > 0 {
		currentHeight = uint64(sdkCtx.BlockHeight())
	}

	for _, task := range tasks {
		if task.Status != types.TaskStatusOpen {
			continue
		}
		if task.CommitHash == "" || task.RevealDeadlineHeight == 0 {
			continue
		}
		if currentHeight <= task.RevealDeadlineHeight {
			continue
		}

		task.CommitHash = ""
		task.CommitHeight = 0
		task.RevealDeadlineHeight = 0
		task.Worker = ""
		k.SetTask(ctx, task)

		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent("workload_recover_expired_commit",
				sdk.NewAttribute("task_id", strconv.FormatUint(task.Id, 10)),
			),
		)
	}

	return nil
}
