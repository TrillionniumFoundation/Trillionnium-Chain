package keeper

import (
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func emitFundFlowEvent(ctx sdk.Context, taskID uint64, from, to string, amount uint64, denom, reason string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent("workload_fund_flow",
			sdk.NewAttribute("task_id", strconv.FormatUint(taskID, 10)),
			sdk.NewAttribute("from", from),
			sdk.NewAttribute("to", to),
			sdk.NewAttribute("amount", strconv.FormatUint(amount, 10)),
			sdk.NewAttribute("denom", denom),
			sdk.NewAttribute("reason", reason),
		),
	)
}
