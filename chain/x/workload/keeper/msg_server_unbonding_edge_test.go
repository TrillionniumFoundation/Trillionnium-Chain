package keeper_test

import (
	"context"
	"errors"
	"testing"

	keepertest "chain/testutil/keeper"
	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdkerrors "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

type failingBankKeeper struct {
	err error
}

func (m failingBankKeeper) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}
func (m failingBankKeeper) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}
func (m failingBankKeeper) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return m.err
}
func (m failingBankKeeper) BurnCoins(context.Context, string, sdk.Coins) error { return nil }

func setupMsgServerWithBankKeeper(t testing.TB, bankKeeper types.BankKeeper) (keeper.Keeper, types.MsgServer, context.Context) {
	k, ctx := keepertest.WorkloadKeeperWithBankKeeper(t, bankKeeper)
	return k, keeper.NewMsgServerImpl(k), ctx
}

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

func countEvents(events sdk.Events, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func assertABCIErrorCode(t *testing.T, err error, expected *sdkerrors.Error) {
	t.Helper()
	require.ErrorIs(t, err, expected)
	codespace, code, _ := sdkerrors.ABCIInfo(err, false)
	require.Equal(t, expected.Codespace(), codespace)
	require.Equal(t, expected.ABCICode(), code)
}

func TestFinalizeUnbonding_BankTransferError_NoFinalizeEvent(t *testing.T) {
	bankErr := errors.New("mock bank send failure")
	k, srv, ctx := setupMsgServerWithBankKeeper(t, failingBankKeeper{err: bankErr})
	sdkCtx := sdk.UnwrapSDKContext(ctx).WithBlockHeight(int64(keeper.UnbondingPeriodBlocks))
	worker := sample.AccAddress()

	k.SetUnbonding(sdkCtx, types.Unbonding{
		Creator:       worker,
		ReleaseHeight: keeper.UnbondingPeriodBlocks,
		Amount:        100000,
	})

	_, err := srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	require.ErrorIs(t, err, bankErr)
	require.Equal(t, 0, countEvents(sdkCtx.EventManager().Events(), "workload_finalize_unbonding"))

	pending, found := k.GetUnbonding(sdkCtx, worker)
	require.True(t, found)
	require.Equal(t, uint64(100000), pending.Amount)
	require.Equal(t, uint64(keeper.UnbondingPeriodBlocks), pending.ReleaseHeight)
}

func TestSetParams_InvalidDenom_Rejected(t *testing.T) {
	k, _, ctx := setupMsgServer(t)
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	err := k.SetParams(sdkCtx, types.Params{WorkloadDenom: ""})
	require.Error(t, err)
	require.Contains(t, err.Error(), "workload denom cannot be empty")
	require.Equal(t, "utrnm", k.GetParams(sdkCtx).WorkloadDenom)
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
	assertABCIErrorCode(t, err, types.ErrUnbondingCooldownNotReached)
	require.Equal(t, 0, countEvents(sdkCtx.EventManager().Events(), "workload_finalize_unbonding"))

	pending, found := k.GetUnbonding(sdkCtx, worker)
	require.True(t, found)
	require.Equal(t, uint64(100000), pending.Amount)
	require.Equal(t, uint64(keeper.UnbondingPeriodBlocks), pending.ReleaseHeight)

	sdkCtx = sdkCtx.WithBlockHeight(int64(keeper.UnbondingPeriodBlocks - 1))
	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	assertABCIErrorCode(t, err, types.ErrUnbondingCooldownNotReached)

	pending, found = k.GetUnbonding(sdkCtx, worker)
	require.True(t, found)
	require.Equal(t, uint64(100000), pending.Amount)
	require.Equal(t, uint64(keeper.UnbondingPeriodBlocks), pending.ReleaseHeight)

	sdkCtx = sdkCtx.WithBlockHeight(int64(keeper.UnbondingPeriodBlocks))
	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)
	require.Equal(t, 1, countEvents(sdkCtx.EventManager().Events(), "workload_finalize_unbonding"))
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "worker", worker))
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "amount", "100000"))
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "denom", "utrnm"))

	_, found = k.GetUnbonding(sdkCtx, worker)
	require.False(t, found)

	before := countEvents(sdkCtx.EventManager().Events(), "workload_finalize_unbonding")
	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: worker})
	assertABCIErrorCode(t, err, types.ErrUnbondingNotFound)
	after := countEvents(sdkCtx.EventManager().Events(), "workload_finalize_unbonding")
	require.Equal(t, before, after)
}
