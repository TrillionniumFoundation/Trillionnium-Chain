package keeper

import (
	"context"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) UnregisterWorker(goCtx context.Context, msg *types.MsgUnregisterWorker) (*types.MsgUnregisterWorkerResponse, error) {
	_ = sdk.UnwrapSDKContext(goCtx)
	_ = msg

	// Deprecated path: direct unregister/withdraw is disabled to enforce cooldown safety.
	// Use `request-unbonding` and then `finalize-unbonding` after release height.
	return nil, sdkerrors.ErrInvalidRequest.Wrap("direct unregister disabled; use request-unbonding then finalize-unbonding")
}
