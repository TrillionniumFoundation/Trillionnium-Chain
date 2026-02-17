package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestFinalizeUnbonding_StateConsistency(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)

	// 1. Setup a worker with stake
	workerAddr := sample.AccAddress()
	stakeAmount := uint64(1000)
	k.SetWorker(wctx, types.Worker{
		Creator: workerAddr,
		Stake:   stakeAmount,
		NodeId:  "node-1",
	})

	// 2. Request Unbonding
	// This should remove the worker and create an unbonding record
	_, err := srv.RequestUnbonding(wctx, &types.MsgRequestUnbonding{
		Creator: workerAddr,
	})
	require.NoError(t, err)

	// Verify Worker is removed
	_, found := k.GetWorker(wctx, workerAddr)
	require.False(t, found, "Worker record should be removed after requesting unbonding")

	// Verify Unbonding record exists
	unbonding, found := k.GetUnbonding(wctx, workerAddr)
	require.True(t, found, "Unbonding record should exist")
	require.Equal(t, stakeAmount, unbonding.Amount)

	// 3. Fast forward time (block height) to pass the unbonding period
	// We need to simulate a block height > ReleaseHeight
	releaseHeight := unbonding.ReleaseHeight
	futureCtx := wctx.WithBlockHeight(int64(releaseHeight + 1))

	// 4. Finalize Unbonding
	_, err = srv.FinalizeUnbonding(futureCtx, &types.MsgFinalizeUnbonding{
		Creator: workerAddr,
	})
	require.NoError(t, err, "FinalizeUnbonding should succeed after unbonding period")

	// 5. Verify State Consistency
	// Worker record should STILL be gone (no zombie state)
	_, found = k.GetWorker(futureCtx, workerAddr)
	require.False(t, found, "Worker record should remain absent after finalization")

	// Unbonding record should be gone
	_, found = k.GetUnbonding(futureCtx, workerAddr)
	require.False(t, found, "Unbonding record should be removed after finalization")
}

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
