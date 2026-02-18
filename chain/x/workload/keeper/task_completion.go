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

// CompleteTask is a privileged method for other modules (like x/compute) to complete a task.
// It applies the same settlement policy as MsgUpdateTask completion path:
// - task must exist and not already be completed
// - 100% escrowed bounty is burned from module account
// - worker/result are persisted and completion event is emitted
func (k Keeper) CompleteTask(ctx context.Context, taskID uint64, workerAddress string, resultHash string) error {
	val, found := k.GetTask(ctx, taskID)
	if !found {
		return errorsmod.Wrap(sdkerrors.ErrKeyNotFound, fmt.Sprintf("task %d not found", taskID))
	}

	if val.Status == 2 { // 2 = COMPLETED
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "task already completed")
	}

	denom := k.workloadDenom(ctx)
	if val.Bounty > 0 {
		if k.bankKeeper == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "bank keeper is not configured")
		}
		bountyCoin := sdk.NewCoin(denom, math.NewIntFromUint64(val.Bounty))
		coins := sdk.NewCoins(bountyCoin)
		if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
	}

	val.Status = 2 // COMPLETED
	val.Worker = workerAddress
	val.ResultHash = resultHash
	k.SetTask(ctx, val)

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("workload_update_task",
			sdk.NewAttribute("task_id", strconv.FormatUint(taskID, 10)),
			sdk.NewAttribute("status", "2"),
			sdk.NewAttribute("worker", workerAddress),
			sdk.NewAttribute("burned", strconv.FormatUint(val.Bounty, 10)),
			sdk.NewAttribute("denom", denom),
		),
	)

	return nil
}
