package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// Regression: first appended challenge has id=0 and must still be treated as an existing challenge.
func TestChallengeIDZero_IsValidChallenge(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	sdkCtx := sdk.UnwrapSDKContext(ctx).WithBlockHeight(10)
	wctx := sdk.WrapSDKContext(sdkCtx)

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, uint64(3), task.Status) // challenged
	require.Equal(t, uint64(0), task.ChallengeId)

	// Auto finalize should not finalize challenged task even when deadline has passed.
	futureCtx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(wctx).WithBlockHeight(1000))
	err = k.AutoFinalizeSubmittedTasks(futureCtx)
	require.NoError(t, err)

	taskAfter, found := k.GetTask(futureCtx, 0)
	require.True(t, found)
	require.Equal(t, uint64(3), taskAfter.Status)
}
