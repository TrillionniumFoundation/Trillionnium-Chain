package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestChallengeResult_LocksChallengeDeposit(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)
	wctx := sdk.WrapSDKContext(ctx.WithBlockHeight(10))

	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 100})
	require.NoError(t, err)
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.NoError(t, err)

	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "bad"})
	require.NoError(t, err)

	require.NotEmpty(t, bank.sendAccountToModuleOps)
	params := k.GetParams(ctx)
	require.Equal(t, int64(params.ChallengeDeposit), bank.lastSendAccountToModule.AmountOf(params.WorkloadDenom).Int64())
}

func TestResolveChallenge_Failed_BurnsPenaltyRefundsAndCompletes(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)
	sdkCtx := ctx.WithBlockHeight(20)
	wctx := sdk.WrapSDKContext(sdkCtx)

	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 100})
	require.NoError(t, err)
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h1"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "bad"})
	require.NoError(t, err)

	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{Creator: k.GetAuthority(), TaskId: 0, ChallengeSucceeded: false})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusCompleted, task.Status)

	params := k.GetParams(ctx)
	penalty := params.ChallengeDeposit * params.ChallengerSlashPercent / 100
	refund := params.ChallengeDeposit - penalty

	require.NotEmpty(t, bank.sendModuleToAccountOps)
	require.Equal(t, int64(refund), bank.lastSendModuleToAccount.AmountOf(params.WorkloadDenom).Int64())

	// burnOps should include challenge penalty burn and task bounty burn
	require.GreaterOrEqual(t, len(bank.burnOps), 2)
	require.Equal(t, int64(penalty), bank.burnOps[len(bank.burnOps)-2].AmountOf(params.WorkloadDenom).Int64())
	require.Equal(t, int64(100), bank.burnOps[len(bank.burnOps)-1].AmountOf(params.WorkloadDenom).Int64())
}

func TestAutoFinalizeSubmittedTasks(t *testing.T) {
	k, _, ctx, _ := setupMsgServerWithSpyBank(t)

	taskID := k.AppendTask(ctx, types.Task{
		Creator:                 sample.AccAddress(),
		Bounty:                  55,
		Status:                  types.TaskStatusRevealed,
		Worker:                  sample.AccAddress(),
		ResultHash:              "h-auto",
		ChallengeDeadlineHeight: 10,
	})

	futureCtx := ctx.WithBlockHeight(11)
	err := k.AutoFinalizeSubmittedTasks(futureCtx)
	require.NoError(t, err)

	task, found := k.GetTask(futureCtx, taskID)
	require.True(t, found)
	require.Equal(t, types.TaskStatusCompleted, task.Status)
}
