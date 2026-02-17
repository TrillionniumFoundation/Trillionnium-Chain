package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"

	"chain/x/workload/types"
)

func TestTaskMsgServerCreate(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)

	creator := "A"
	for i := 0; i < 5; i++ {
		resp, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator})
		require.NoError(t, err)
		require.Equal(t, i, int(resp.Id))
	}
}

func TestTaskMsgServerUpdate(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgUpdateTask
		err     error
	}{
		{
			desc:    "Completed",
			request: &types.MsgUpdateTask{Creator: creator},
		},
		{
			desc:    "Unauthorized",
			request: &types.MsgUpdateTask{Creator: "B"},
			err:     sdkerrors.ErrUnauthorized,
		},
		{
			desc:    "Unauthorized",
			request: &types.MsgUpdateTask{Creator: creator, Id: 10},
			err:     sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, srv, ctx := setupMsgServer(t)
			wctx := sdk.UnwrapSDKContext(ctx)

			_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator})
			require.NoError(t, err)

			_, err = srv.UpdateTask(wctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTaskMsgServerDelete(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgDeleteTask
		err     error
	}{
		{
			desc:    "Completed",
			request: &types.MsgDeleteTask{Creator: creator},
		},
		{
			desc:    "Unauthorized",
			request: &types.MsgDeleteTask{Creator: "B"},
			err:     sdkerrors.ErrUnauthorized,
		},
		{
			desc:    "KeyNotFound",
			request: &types.MsgDeleteTask{Creator: creator, Id: 10},
			err:     sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, srv, ctx := setupMsgServer(t)
			wctx := sdk.UnwrapSDKContext(ctx)

			_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator})
			require.NoError(t, err)
			_, err = srv.DeleteTask(wctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
