package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestFinalizeUnbonding_NotFound(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)

	// Case: User has never requested unbonding (no entry in store)
	randomUser := sample.AccAddress()

	// Ensure no unbonding exists initially
	_, found := k.GetUnbonding(wctx, randomUser)
	require.False(t, found, "Unbonding should not exist for random user")

	// Attempt to finalize
	_, err := srv.FinalizeUnbonding(wctx, &types.MsgFinalizeUnbonding{
		Creator: randomUser,
	})

	// Assertions
	require.ErrorIs(t, err, types.ErrUnbondingNotFound, "Should return ErrUnbondingNotFound when no unbonding exists")
	
	// Double check state remains unchanged (still not found)
	_, found = k.GetUnbonding(wctx, randomUser)
	require.False(t, found, "State should remain unchanged (unbonding not created)")
}
