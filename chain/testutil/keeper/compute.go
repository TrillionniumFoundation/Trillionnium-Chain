package keeper

import (
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

	"chain/x/compute/keeper"
	"chain/x/compute/types"
	workloadkeeper "chain/x/workload/keeper"
)

func ComputeKeeper(t testing.TB) (keeper.Keeper, sdk.Context) {
	k, _, ctx := ComputeKeeperWithWorkload(t)
	return k, ctx
}

func ComputeKeeperWithWorkload(t testing.TB) (keeper.Keeper, workloadkeeper.Keeper, sdk.Context) {
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	workloadStoreKey := storetypes.NewKVStoreKey("workload")

	db := dbm.NewMemDB()
	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	stateStore.MountStoreWithDB(workloadStoreKey, storetypes.StoreTypeIAVL, db)
	require.NoError(t, stateStore.LoadLatestVersion())

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)

	workloadK := workloadkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(workloadStoreKey),
		log.NewNopLogger(),
		authority.String(),
		nil,
		nil,
	)

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		log.NewNopLogger(),
		authority.String(),
		nil,
		nil,
		workloadK,
	)

	ctx := sdk.NewContext(stateStore, cmtproto.Header{}, false, log.NewNopLogger())

	// Initialize params
	k.SetParams(ctx, types.DefaultParams())

	return k, workloadK, ctx
}
