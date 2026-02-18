package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestFundFlowEvent_BountyLockAndChallengeDepositAndRefund(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(100))

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1_000_000})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "r"})
	require.NoError(t, err)
	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{Creator: k.GetAuthority(), TaskId: 0, ChallengeSucceeded: true})
	require.NoError(t, err)

	events := sdk.UnwrapSDKContext(wctx).EventManager().Events()
	reasons := collectFundFlowReasons(events)
	require.Contains(t, reasons, "bounty_lock")
	require.Contains(t, reasons, "challenge_deposit")
	require.Contains(t, reasons, "challenge_refund")
	require.Contains(t, reasons, "worker_slash")
}

func TestFundFlowEvent_ChallengeBurnAndTaskBurn(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()
	challenger := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(120))

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1_000_000})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.SubmitResult(wctx, &types.MsgSubmitResult{Creator: worker, TaskId: 0, ResultHash: "h"})
	require.NoError(t, err)
	_, err = srv.ChallengeResult(wctx, &types.MsgChallengeResult{Creator: challenger, TaskId: 0, Reason: "r"})
	require.NoError(t, err)
	_, err = srv.ResolveChallenge(wctx, &types.MsgResolveChallenge{Creator: k.GetAuthority(), TaskId: 0, ChallengeSucceeded: false, FinalResultHash: "ok"})
	require.NoError(t, err)

	events := sdk.UnwrapSDKContext(wctx).EventManager().Events()
	reasons := collectFundFlowReasons(events)
	require.Contains(t, reasons, "challenge_burn")
	require.Contains(t, reasons, "challenge_refund")
	require.Contains(t, reasons, "task_burn")
}

func collectFundFlowReasons(events sdk.Events) []string {
	var out []string
	for _, ev := range events {
		if ev.Type != "workload_fund_flow" {
			continue
		}
		for _, attr := range ev.Attributes {
			if string(attr.Key) == "reason" {
				out = append(out, string(attr.Value))
			}
		}
	}
	return out
}
