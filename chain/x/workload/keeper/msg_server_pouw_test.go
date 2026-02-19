package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestSubmitResultLegacyDisabledByDefault(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(10))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "legacy submit_result is disabled")
}

func TestPoUWSubmitChallengeResolve(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	challenger := sample.AccAddress()
	worker := sample.AccAddress()

	sdkCtx := sdk.UnwrapSDKContext(ctx).WithBlockHeight(10)
	wctx := sdk.WrapSDKContext(sdkCtx)

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)

	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusRevealed, task.Status)
	require.Equal(t, uint64(10)+k.GetParams(wctx).ChallengeWindowBlocks, task.ChallengeDeadlineHeight)

	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "bad"})
	require.NoError(t, err)

	task, found = k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusChallenged, task.Status)

	ch, found := k.GetChallenge(wctx, task.ChallengeId)
	require.True(t, found)
	require.Equal(t, challenger, ch.Challenger)
	require.Equal(t, worker, ch.Worker)

	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{
		Creator:            k.GetAuthority(),
		TaskId:             0,
		ChallengeSucceeded: true,
	})
	require.NoError(t, err)

	task, _ = k.GetTask(wctx, 0)
	require.Equal(t, types.TaskStatusSlashed, task.Status)
	ch, _ = k.GetChallenge(wctx, task.ChallengeId)
	require.Equal(t, uint64(1), ch.Status)
}

func TestChallengeAfterDeadlineFails(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	sdkCtx := sdk.UnwrapSDKContext(ctx).WithBlockHeight(100)
	wctx := sdk.WrapSDKContext(sdkCtx)

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h"})
	require.NoError(t, err)

	lateCtx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(wctx).WithBlockHeight(1000))
	_, err = srv.ChallengeResult(lateCtx, &types.MsgChallengeResult{Creator: sample.AccAddress(), TaskId: 0})
	require.ErrorIs(t, err, types.ErrChallengeWindowExpired)
}

func TestChallengeResult_SecondChallengeRejectedEvenWhenFirstChallengeIDIsZero(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger1 := sample.AccAddress()
	challenger2 := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(30))

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h"})
	require.NoError(t, err)

	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger1, TaskId: 0})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusChallenged, task.Status)
	require.Equal(t, uint64(0), task.ChallengeId) // first challenge id can be zero

	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger2, TaskId: 0})
	require.ErrorIs(t, err, types.ErrInvalidTaskStateTransition)
}

func TestResolveChallengeUnauthorized(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(20))
	_, _ = srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, _ = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h"})
	_, _ = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0})

	_, err := srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{Creator: sample.AccAddress(), TaskId: 0})
	require.ErrorIs(t, err, types.ErrUnauthorizedSlash)
}
