package keeper_test

import (
	"context"
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

type fixedResolver struct {
	out types.DisputeResolveOutput
	err error
}

func (r fixedResolver) Resolve(_ context.Context, _ types.DisputeResolveInput) (types.DisputeResolveOutput, error) {
	return r.out, r.err
}

func TestResolveChallenge_UsesInjectedDisputeResolver(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	k.SetDisputeResolver(fixedResolver{out: types.DisputeResolveOutput{
		ChallengeStatus: types.ChallengeStatusRejected,
		TaskStatus:      types.TaskStatusCompleted,
		FinalResultHash: "resolver-final-hash",
	}})
	srv = keeper.NewMsgServerImpl(k)

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(50))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h0"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "r"})
	require.NoError(t, err)

	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{
		Creator:            k.GetAuthority(),
		TaskId:             0,
		ChallengeSucceeded: true,
		FinalResultHash:    "ignored-by-fixed-resolver",
	})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusCompleted, task.Status)
	require.Equal(t, "resolver-final-hash", task.ResultHash)

	ch, found := k.GetChallenge(wctx, task.ChallengeId)
	require.True(t, found)
	require.Equal(t, types.ChallengeStatusRejected, ch.Status)
}

func TestSetDisputeResolver_NilFallsBackToDefault(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	params := k.GetParams(ctx)
	params.AllowLegacySubmitResult = true
	require.NoError(t, k.SetParams(ctx, params))
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	k.SetDisputeResolver(nil)
	srv = keeper.NewMsgServerImpl(k)

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(60))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "r"})
	require.NoError(t, err)

	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{
		Creator:            k.GetAuthority(),
		TaskId:             0,
		ChallengeSucceeded: true,
	})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusSlashed, task.Status)
}
