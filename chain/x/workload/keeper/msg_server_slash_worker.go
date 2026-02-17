package keeper

import (
	"context"
	"strconv"

	"chain/x/workload/types"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const MinWorkerStakeAfterSlash uint64 = 1000

func (k msgServer) SlashWorker(goCtx context.Context, msg *types.MsgSlashWorker) (*types.MsgSlashWorkerResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// governance-only slashing: only module authority can trigger slashing
	if msg.Creator != k.GetAuthority() {
		return nil, sdkerrors.ErrUnauthorized.Wrap("only authority can slash worker")
	}

	// only active workers can be slashed
	worker, found := k.GetWorker(ctx, msg.Worker)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound.Wrap("active worker not found")
	}

	if msg.SlashPercent == 0 || msg.SlashPercent > 50 {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("slash percent must be between 1 and 50")
	}

	slashAmount := worker.Stake * msg.SlashPercent / 100
	if slashAmount == 0 {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("slash amount is zero")
	}

	remaining := worker.Stake - slashAmount
	if remaining < MinWorkerStakeAfterSlash {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("slash would violate minimum remaining worker stake")
	}

	coins := sdk.NewCoins(sdk.NewCoin("stake", math.NewIntFromUint64(slashAmount)))
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return nil, err
	}

	worker.Stake = remaining
	k.SetWorker(ctx, worker)

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
