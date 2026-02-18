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

const MinWorkerStakeAfterSlash uint64 = 1000

func (k msgServer) SlashWorker(goCtx context.Context, msg *types.MsgSlashWorker) (*types.MsgSlashWorkerResponse, error) {
	if msg == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "request cannot be nil")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	// governance-only slashing: only module authority can trigger slashing
	if msg.Creator != k.GetAuthority() {
		return nil, types.ErrUnauthorizedSlash
	}

	// only active workers can be slashed
	worker, found := k.GetWorker(ctx, msg.Worker)
	if !found {
		return nil, types.ErrWorkerNotFound
	}

	if msg.SlashPercent == 0 || msg.SlashPercent > 50 {
		return nil, types.ErrInvalidSlashPercent
	}

	slashAmount := worker.Stake * msg.SlashPercent / 100
	if slashAmount == 0 {
		return nil, types.ErrInvalidSlashAmount
	}

	remaining := worker.Stake - slashAmount
	if remaining < MinWorkerStakeAfterSlash {
		return nil, types.ErrMinRemainingStakeViolation
	}

	coins := sdk.NewCoins(sdk.NewCoin(k.workloadDenom(ctx), math.NewIntFromUint64(slashAmount)))
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return nil, err
	}

	worker.Stake = remaining
	k.SetWorker(ctx, worker)
	emitFundFlowEvent(ctx, 0, msg.Worker, "burn", slashAmount, k.workloadDenom(ctx), "worker_slash")

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_slash_worker",
			sdk.NewAttribute("worker", msg.Worker),
			sdk.NewAttribute("slash_percent", strconv.FormatUint(msg.SlashPercent, 10)),
			sdk.NewAttribute("slash_amount", strconv.FormatUint(slashAmount, 10)),
			sdk.NewAttribute("remaining_stake", strconv.FormatUint(remaining, 10)),
		),
	)

	return &types.MsgSlashWorkerResponse{}, nil
}
