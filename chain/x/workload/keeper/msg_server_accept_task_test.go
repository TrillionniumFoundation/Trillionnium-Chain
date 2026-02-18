package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestAcceptTask_SetsAssignedWorker(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(10))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: worker, TaskId: 0})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, worker, task.Worker)
	require.Equal(t, types.TaskStatusAssigned, task.Status)
}

func TestAcceptTask_RequiresRegisteredWorker(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(10))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)

	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: worker, TaskId: 0})
	require.ErrorIs(t, err, types.ErrWorkerNotFound)
}

func TestAcceptTask_RejectsNonOpenTask(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(10))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

	task, _ := k.GetTask(wctx, 0)
	task.Status = types.TaskStatusCompleted
	k.SetTask(wctx, task)

	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: worker, TaskId: 0})
	require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
}
