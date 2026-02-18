package keeper

import (
	"context"
)

// AutoFinalizeSubmittedTasks finalizes tasks that passed challenge window without challenge.
func (k Keeper) AutoFinalizeSubmittedTasks(ctx context.Context) error {
	tasks := k.GetAllTask(ctx)
	currentHeight := uint64(0)
	if sdkCtx, ok := ctx.(interface{ BlockHeight() int64 }); ok {
		if sdkCtx.BlockHeight() > 0 {
			currentHeight = uint64(sdkCtx.BlockHeight())
		}
	}

	for _, task := range tasks {
		if task.Status != 1 { // RESULT_SUBMITTED
			continue
		}
		if currentHeight <= task.ChallengeDeadlineHeight {
			continue
		}
		if err := k.CompleteTask(ctx, task.Id, task.Worker, task.ResultHash); err != nil {
			return err
		}
	}

	return nil
}
