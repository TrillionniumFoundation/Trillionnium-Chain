package keeper

import (
	"context"
	"testing"

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

	"chain/x/workload/keeper"
	"chain/x/workload/types"
)

type mockBankKeeper struct{}

func (m mockBankKeeper) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}
func (m mockBankKeeper) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}
func (m mockBankKeeper) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return nil
}
func (m mockBankKeeper) BurnCoins(context.Context, string, sdk.Coins) error { return nil }

func WorkloadKeeper(t testing.TB) (keeper.Keeper, sdk.Context) {
	return WorkloadKeeperWithBankKeeper(t, mockBankKeeper{})
}

func WorkloadKeeperWithBankKeeper(t testing.TB, bankKeeper types.BankKeeper) (keeper.Keeper, sdk.Context) {
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	db := dbm.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, stateStore.LoadLatestVersion())

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		log.NewNopLogger(),
		authority.String(),
		bankKeeper,
		nil,
	)

	ctx := sdk.NewContext(stateStore, cmtproto.Header{}, false, log.NewNopLogger())

	// Initialize params
	k.SetParams(ctx, types.DefaultParams())

	return k, ctx
}
