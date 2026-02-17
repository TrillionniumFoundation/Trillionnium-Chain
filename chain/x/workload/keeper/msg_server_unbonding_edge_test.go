package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestExtendUnbonding_Edges(t *testing.T) {
	t.Run("extra blocks zero", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)
		worker := sample.AccAddress()
		k.SetUnbonding(wctx, types.Unbonding{Creator: worker, ReleaseHeight: 100, Amount: 100000})

		_, err := srv.ExtendUnbonding(wctx, &types.MsgExtendUnbonding{
			Creator:     k.GetAuthority(),
			Worker:      worker,
			ExtraBlocks: 0,
		})
		require.ErrorIs(t, err, types.ErrInvalidExtraBlocks)
	})

	t.Run("extra blocks exceeds max", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)
		worker := sample.AccAddress()
		k.SetUnbonding(wctx, types.Unbonding{Creator: worker, ReleaseHeight: 100, Amount: 100000})

		_, err := srv.ExtendUnbonding(wctx, &types.MsgExtendUnbonding{
			Creator:     k.GetAuthority(),
			Worker:      worker,
			ExtraBlocks: keeper.MaxExtraUnbondingBlocks + 1,
		})
		require.ErrorIs(t, err, types.ErrInvalidExtraBlocks)
	})

	t.Run("unbonding not found", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)

		_, err := srv.ExtendUnbonding(wctx, &types.MsgExtendUnbonding{
			Creator:     k.GetAuthority(),
			Worker:      sample.AccAddress(),
			ExtraBlocks: 10,
		})
		require.ErrorIs(t, err, types.ErrUnbondingNotFound)
	})

	t.Run("success", func(t *testing.T) {
		k, srv, ctx := setupMsgServer(t)
		wctx := sdk.UnwrapSDKContext(ctx)
		worker := sample.AccAddress()
		k.SetUnbonding(wctx, types.Unbonding{Creator: worker, ReleaseHeight: 100, Amount: 100000})

		_, err := srv.ExtendUnbonding(wctx, &types.MsgExtendUnbonding{
			Creator:     k.GetAuthority(),
			Worker:      worker,
			ExtraBlocks: 25,
		})
		require.NoError(t, err)

		u, found := k.GetUnbonding(wctx, worker)
		require.True(t, found)
		require.Equal(t, uint64(125), u.ReleaseHeight)
	})
}

func hasEventAttribute(events sdk.Events, eventType, key, expected string) bool {
	for _, event := range events {
		if event.Type != eventType {
			continue
		}
		for _, attr := range event.Attributes {
			if string(attr.Key) == key && string(attr.Value) == expected {
				return true
			}
		}
	}
	return false
}

func TestFinalizeUnbonding_HeightEdges(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	worker := sample.AccAddress()
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	k.SetUnbonding(sdkCtx, types.Unbonding{
		Creator:       worker,
		ReleaseHeight: uint64(sdkCtx.BlockHeight()) + keeper.UnbondingPeriodBlocks,
		Amount:        100000,
	})

	_, err := srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	require.ErrorIs(t, err, types.ErrUnbondingCooldownNotReached)

	sdkCtx = sdkCtx.WithBlockHeight(int64(keeper.UnbondingPeriodBlocks))
	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)

	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "worker", worker))
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "amount", "100000"))

	_, found := k.GetUnbonding(sdkCtx, worker)
	require.False(t, found)

	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	require.ErrorIs(t, err, types.ErrUnbondingNotFound)
}
