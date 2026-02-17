package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdktypeerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgServer_NilRequestsRejected(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "register worker",
			call: func() error {
				_, err := srv.RegisterWorker(sdkCtx, nil)
				return err
			},
		},
		{
			name: "slash worker",
			call: func() error {
				_, err := srv.SlashWorker(sdkCtx, nil)
				return err
			},
		},
		{
			name: "create task",
			call: func() error {
				_, err := srv.CreateTask(sdkCtx, nil)
				return err
			},
		},
		{
			name: "update task",
			call: func() error {
				_, err := srv.UpdateTask(sdkCtx, nil)
				return err
			},
		},
		{
			name: "delete task",
			call: func() error {
				_, err := srv.DeleteTask(sdkCtx, nil)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.ErrorIs(t, err, sdktypeerrors.ErrInvalidRequest)
			require.Contains(t, err.Error(), "request cannot be nil")
		})
	}
}
