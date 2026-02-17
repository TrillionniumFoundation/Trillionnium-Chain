package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestSlashWorker_Edges(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      sample.AccAddress(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.ErrorIs(t, err, types.ErrUnauthorizedSlash)
	})

	t.Run("worker not found", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       sample.AccAddress(),
			SlashPercent: 10,
		})
		require.ErrorIs(t, err, types.ErrWorkerNotFound)
	})

	t.Run("invalid percent", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 0,
		})
		require.ErrorIs(t, err, types.ErrInvalidSlashPercent)

		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 51,
		})
		require.ErrorIs(t, err, types.ErrInvalidSlashPercent)
	})

	t.Run("min remaining stake violation", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 1000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.ErrorIs(t, err, types.ErrMinRemainingStakeViolation)
	})

	t.Run("success", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, found := k.GetWorker(wctx, worker)
		require.True(t, found)
		require.Equal(t, uint64(50000), w.Stake)
	})
}
