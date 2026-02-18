package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestAutoRecoverExpiredCommits(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(100))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	task.Worker = worker
	task.CommitHash = "stale-commit"
	task.CommitHeight = 100
	task.RevealDeadlineHeight = 120
	task.Status = types.TaskStatusCommitted
	k.SetTask(wctx, task)

	err = k.AutoRecoverExpiredCommits(sdk.UnwrapSDKContext(wctx).WithBlockHeight(121))
	require.NoError(t, err)

	task, found = k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, "", task.CommitHash)
	require.Equal(t, uint64(0), task.CommitHeight)
	require.Equal(t, uint64(0), task.RevealDeadlineHeight)
	require.Equal(t, "", task.Worker)
}
