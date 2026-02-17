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

	t.Run("repeated slash until limit", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		// Start with enough stake: 10,000
		workerAddr := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{
			Creator: workerAddr,
			Stake:   10000,
		})

		// 1. First slash 50% -> 5,000 left
		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       workerAddr,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ := k.GetWorker(wctx, workerAddr)
		require.Equal(t, uint64(5000), w.Stake)

		// 2. Second slash 50% -> 2,500 left
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       workerAddr,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ = k.GetWorker(wctx, workerAddr)
		require.Equal(t, uint64(2500), w.Stake)

		// 3. Third slash 50% -> 1,250 left
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       workerAddr,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ = k.GetWorker(wctx, workerAddr)
		require.Equal(t, uint64(1250), w.Stake)

		// 4. Fourth slash 50% -> 625 left (Violation of Min 1000)
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       workerAddr,
			SlashPercent: 50,
		})
		require.ErrorIs(t, err, types.ErrMinRemainingStakeViolation)

		// Verify stake didn't change after failure
		w, _ = k.GetWorker(wctx, workerAddr)
		require.Equal(t, uint64(1250), w.Stake)
	})

	t.Run("slash zero or low stake worker", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		// Case A: Worker has exactly Min stake (1000)
		worker1 := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker1, Stake: 1000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker1,
			SlashPercent: 10,
		})
		// 1000 - 100 = 900 < 1000 -> Error
		require.ErrorIs(t, err, types.ErrMinRemainingStakeViolation)

		// Case B: Worker has 0 stake (if theoretically possible in state)
		worker2 := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker2, Stake: 0})

		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker2,
			SlashPercent: 10,
		})
		// 0 * 10% = 0 -> Invalid Slash Amount
		require.ErrorIs(t, err, types.ErrInvalidSlashAmount)
	})
}
