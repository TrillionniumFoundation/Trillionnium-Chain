package keeper_test

import (
	"context"
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	"cosmossdk.io/log"
	"cosmossdk.io/store"
	"cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/stretchr/testify/require"
)

type spyBankKeeper struct {
	lastSendAccountToModule sdk.Coins
	lastSendModuleToAccount sdk.Coins
	lastBurn                sdk.Coins
}

func (s *spyBankKeeper) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}
func (s *spyBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, coins sdk.Coins) error {
	s.lastSendAccountToModule = coins
	return nil
}
func (s *spyBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, coins sdk.Coins) error {
	s.lastSendModuleToAccount = coins
	return nil
}
func (s *spyBankKeeper) BurnCoins(_ context.Context, _ string, coins sdk.Coins) error {
	s.lastBurn = coins
	return nil
}

func setupMsgServerWithSpyBank(t testing.TB) (keeper.Keeper, types.MsgServer, sdk.Context, *spyBankKeeper) {
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	db := dbm.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, stateStore.LoadLatestVersion())

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)
	spyBank := &spyBankKeeper{}

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		log.NewNopLogger(),
		authority.String(),
		spyBank,
		nil,
	)

	ctx := sdk.NewContext(stateStore, cmtproto.Header{}, false, log.NewNopLogger())
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))

	return k, keeper.NewMsgServerImpl(k), ctx, spyBank
}

func TestDenomParamUsedInTaskAndSlash(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)
	wctx := sdk.WrapSDKContext(ctx)

	params := k.GetParams(ctx)
	params.WorkloadDenom = "ufoo"
	require.NoError(t, k.SetParams(ctx, params))

	creator := sample.AccAddress()
	worker := sample.AccAddress()

	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 123})
	require.NoError(t, err)

	_, err = srv.UpdateTask(wctx, &types.MsgUpdateTask{Creator: worker, Id: 0, Status: 2})
	require.NoError(t, err)
	require.Len(t, bank.lastBurn, 1)
	require.Equal(t, "ufoo", bank.lastBurn[0].Denom)
	require.Equal(t, int64(123), bank.lastBurn[0].Amount.Int64())

	k.SetWorker(ctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.SlashWorker(wctx, &types.MsgSlashWorker{Creator: k.GetAuthority(), Worker: worker, SlashPercent: 10})
	require.NoError(t, err)
	require.Len(t, bank.lastBurn, 1)
	require.Equal(t, "ufoo", bank.lastBurn[0].Denom)
	require.Equal(t, int64(10000), bank.lastBurn[0].Amount.Int64())
}

func TestDenomParamUsedInFinalizeUnbonding(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)

	params := k.GetParams(ctx)
	params.WorkloadDenom = "ufoo"
	require.NoError(t, k.SetParams(ctx, params))

	worker := sample.AccAddress()
	k.SetUnbonding(ctx, types.Unbonding{Creator: worker, ReleaseHeight: 10, Amount: 8888})

	sdkCtx := ctx.WithBlockHeight(11)
	_, err := srv.FinalizeUnbonding(sdk.WrapSDKContext(sdkCtx), &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)
	require.Len(t, bank.lastSendModuleToAccount, 1)
	require.Equal(t, "ufoo", bank.lastSendModuleToAccount[0].Denom)
	require.Equal(t, int64(8888), bank.lastSendModuleToAccount[0].Amount.Int64())
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "denom", "ufoo"))
}

func TestFinalizeUnbonding_EmptyDenomFallsBackToDefault(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)

	params := k.GetParams(ctx)
	params.WorkloadDenom = ""
	require.NoError(t, k.SetParams(ctx, params))

	worker := sample.AccAddress()
	k.SetUnbonding(ctx, types.Unbonding{Creator: worker, ReleaseHeight: 10, Amount: 77})

	sdkCtx := ctx.WithBlockHeight(11)
	_, err := srv.FinalizeUnbonding(sdk.WrapSDKContext(sdkCtx), &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)
	require.Len(t, bank.lastSendModuleToAccount, 1)
	require.Equal(t, "utrnm", bank.lastSendModuleToAccount[0].Denom)
	require.Equal(t, int64(77), bank.lastSendModuleToAccount[0].Amount.Int64())
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "denom", "utrnm"))
}

func TestFinalizeUnbonding_ZeroAmountSkipsBankTransfer(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)

	params := k.GetParams(ctx)
	params.WorkloadDenom = "ufoo"
	require.NoError(t, k.SetParams(ctx, params))

	worker := sample.AccAddress()
	k.SetUnbonding(ctx, types.Unbonding{Creator: worker, ReleaseHeight: 10, Amount: 0})

	sdkCtx := ctx.WithBlockHeight(11)
	_, err := srv.FinalizeUnbonding(sdk.WrapSDKContext(sdkCtx), &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)
	require.Empty(t, bank.lastSendModuleToAccount)
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "denom", "ufoo"))

	_, found := k.GetUnbonding(sdkCtx, worker)
	require.False(t, found)
}

func TestFinalizeUnbonding_UsesLatestDenomAtFinalizeBoundary(t *testing.T) {
	k, srv, ctx, bank := setupMsgServerWithSpyBank(t)

	params := k.GetParams(ctx)
	params.WorkloadDenom = "ufoo"
	require.NoError(t, k.SetParams(ctx, params))

	worker := sample.AccAddress()
	k.SetUnbonding(ctx, types.Unbonding{Creator: worker, ReleaseHeight: 10, Amount: 42})

	params.WorkloadDenom = "ubar"
	require.NoError(t, k.SetParams(ctx, params))

	sdkCtx := ctx.WithBlockHeight(10)
	_, err := srv.FinalizeUnbonding(sdk.WrapSDKContext(sdkCtx), &types.MsgFinalizeUnbonding{Creator: worker})
	require.NoError(t, err)
	require.Len(t, bank.lastSendModuleToAccount, 1)
	require.Equal(t, "ubar", bank.lastSendModuleToAccount[0].Denom)
	require.True(t, hasEventAttribute(sdkCtx.EventManager().Events(), "workload_finalize_unbonding", "denom", "ubar"))
}
