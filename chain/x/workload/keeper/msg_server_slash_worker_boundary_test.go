package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestSlashWorker_Boundary(t *testing.T) {
	// Boundary: Exact Minimum Remaining Stake
	t.Run("boundary_exact_min_stake", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		// Start with 2000, slash 50% -> 1000. Should be OK.
		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 2000})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ := k.GetWorker(wctx, worker)
		require.Equal(t, uint64(1000), w.Stake)

		// Further slash should fail if it goes below 1000
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 1, // 1000 * 1% = 10 -> 990 < 1000
		})
		require.ErrorIs(t, err, types.ErrMinRemainingStakeViolation)
	})

	// Boundary: Just Below Minimum Remaining Stake (Edge Case Check)
	t.Run("boundary_just_below_min_stake", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		// Start with 1999, slash 50% -> 999.
		// Remaining = 1999 - 999 = 1000. This is EXACTLY the minimum.
		// So this should SUCCEED, not fail.
		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 1999})

		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ := k.GetWorker(wctx, worker)
		require.Equal(t, uint64(1000), w.Stake)

		// NOW if we slash again, it should fail (even 1%)
		// 1% of 1000 is 10. Remaining 990.
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 1,
		})
		require.ErrorIs(t, err, types.ErrMinRemainingStakeViolation)
	})

	// Boundary: Multiple Slashes
	t.Run("boundary_multiple_slashes", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 10000})

		// Slash 1: 50% -> 5000
		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 50,
		})
		require.NoError(t, err)

		w, _ := k.GetWorker(wctx, worker)
		require.Equal(t, uint64(5000), w.Stake)

		// Slash 2: 20% -> 4000
		_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 20,
		})
		require.NoError(t, err)

		w, _ = k.GetWorker(wctx, worker)
		require.Equal(t, uint64(4000), w.Stake)
	})

	// Boundary: Tiny Slash (Zero Amount)
	t.Run("boundary_tiny_slash_zero_amount", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		// Start with 1005. 1% of 1005 is 10. Wait, 1005 * 1 / 100 = 10.05 -> 10.
		// Let's try to get 0. Need stake < 100 for 1% slash to be 0.
		// But stake must remain >= 1000.
		// So if stake is 1005, slash 1% -> amount 10. Remaining 995. Fail.

		// If we set stake to say 500 (already below min, maybe from genesis or bug), and try to slash 1% -> 5. Remaining 495. Fail.

		// What if we try to slash 0%? No, validation catches that.
		// What if we slash such a small amount that integer math makes it 0?
		// e.g. Stake 10000. 0.001%? Field is uint64, so min is 1%.
		// So min slash amount for stake 1000 is 10.
		// Min slash amount for stake 1 is 0.

		// So if stake is < 100, 1% slash is 0.
		// But if stake is < 100, it's already below 1000.
		// Let's force a worker with 90 stake.
		worker := sample.AccAddress()
		k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 90})

		// 1% of 90 is 0.
		_, err := srv.SlashWorker(wctx, &types.MsgSlashWorker{
			Creator:      k.GetAuthority(),
			Worker:       worker,
			SlashPercent: 1,
		})
		// Should fail because slash amount is 0 OR remaining stake violation.
		// Implementation check: slashAmount == 0 -> ErrInvalidSlashAmount.
		require.ErrorIs(t, err, types.ErrInvalidSlashAmount)
	})
}
