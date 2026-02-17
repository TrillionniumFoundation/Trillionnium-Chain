package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetUnbonding set a specific unbonding in the store from its index
func (k Keeper) SetUnbonding(ctx context.Context, unbonding types.Unbonding) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.UnbondingKeyPrefix))
	b := k.cdc.MustMarshal(&unbonding)
	store.Set(types.UnbondingKey(
		unbonding.Creator,
	), b)
}

// GetUnbonding returns a unbonding from its index
func (k Keeper) GetUnbonding(
	ctx context.Context,
	creator string,

) (val types.Unbonding, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.UnbondingKeyPrefix))

	b := store.Get(types.UnbondingKey(
		creator,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveUnbonding removes a unbonding from the store
func (k Keeper) RemoveUnbonding(
	ctx context.Context,
	creator string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.UnbondingKeyPrefix))
	store.Delete(types.UnbondingKey(
		creator,
	))
}

// GetAllUnbonding returns all unbonding
func (k Keeper) GetAllUnbonding(ctx context.Context) (list []types.Unbonding) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.UnbondingKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Unbonding
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
