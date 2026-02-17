package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetWorker set a specific worker in the store from its index
func (k Keeper) SetWorker(ctx context.Context, worker types.Worker) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WorkerKeyPrefix))
	b := k.cdc.MustMarshal(&worker)
	store.Set(types.WorkerKey(
		worker.Creator,
	), b)
}

// GetWorker returns a worker from its index
func (k Keeper) GetWorker(
	ctx context.Context,
	creator string,

) (val types.Worker, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WorkerKeyPrefix))

	b := store.Get(types.WorkerKey(
		creator,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveWorker removes a worker from the store
func (k Keeper) RemoveWorker(
	ctx context.Context,
	creator string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WorkerKeyPrefix))
	store.Delete(types.WorkerKey(
		creator,
	))
}

// GetAllWorker returns all worker
func (k Keeper) GetAllWorker(ctx context.Context) (list []types.Worker) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.WorkerKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Worker
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
