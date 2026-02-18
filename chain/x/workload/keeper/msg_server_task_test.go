package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestTaskMsgServerCreate(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)

	creator := sample.AccAddress()
	for i := 0; i < 3; i++ {
		resp, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
		require.NoError(t, err)
		require.Equal(t, i, int(resp.Id))
	}
}

func TestTaskMsgServerUpdate(t *testing.T) {
	creator := sample.AccAddress()
	other := sample.AccAddress()

	t.Run("AuthorityOnly", func(t *testing.T) {
		_, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
		require.NoError(t, err)

		_, err = srv.UpdateTask(wctx, &types.MsgUpdateTask{Creator: other, Id: 0, Status: 1})
		require.ErrorIs(t, err, types.ErrUnauthorizedSlash)
	})

	t.Run("AuthorityCanUpdate", func(t *testing.T) {
		k, _, ctx := setupMsgServer(t)
		srv := keeper.NewMsgServerImpl(k)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
		require.NoError(t, err)

		_, err = srv.UpdateTask(wctx, &types.MsgUpdateTask{Creator: k.GetAuthority(), Id: 0, Status: 1})
		require.NoError(t, err)
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		k, _, ctx := setupMsgServer(t)
		srv := keeper.NewMsgServerImpl(k)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.UpdateTask(wctx, &types.MsgUpdateTask{Creator: k.GetAuthority(), Id: 99, Status: 1})
		require.ErrorIs(t, err, sdkerrors.ErrKeyNotFound)
	})
}

func TestTaskMsgServerDelete(t *testing.T) {
	creator := sample.AccAddress()
	other := sample.AccAddress()

	t.Run("Completed", func(t *testing.T) {
		_, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
		require.NoError(t, err)

		_, err = srv.DeleteTask(wctx, &types.MsgDeleteTask{Creator: creator, Id: 0})
		require.NoError(t, err)
	})

	t.Run("Unauthorized", func(t *testing.T) {
		_, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
		require.NoError(t, err)

		_, err = srv.DeleteTask(wctx, &types.MsgDeleteTask{Creator: other, Id: 0})
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	})
}
