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

func TestFinalizeUnbonding_NoRequest_Fails(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)

	// Random user who has not made any unbonding request
	user := sample.AccAddress()

	// Pre-check: Ensure no unbonding record exists
	_, found := k.GetUnbonding(wctx, user)
	require.False(t, found, "Unbonding record should not exist initially")

	// Action: Attempt to finalize unbonding
	msg := &types.MsgFinalizeUnbonding{
		Creator: user,
	}
	_, err := srv.FinalizeUnbonding(wctx, msg)

	// Assertion: Should return ErrUnbondingNotFound
	require.ErrorIs(t, err, types.ErrUnbondingNotFound, "Expected ErrUnbondingNotFound when finalizing without request")

	// Post-check: Ensure state is unchanged (still no record)
	_, found = k.GetUnbonding(wctx, user)
	require.False(t, found, "Unbonding record should still not exist")
}
