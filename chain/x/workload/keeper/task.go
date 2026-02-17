package keeper

import (
	"context"
	"encoding/binary"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// GetTaskCount get the total number of task
func (k Keeper) GetTaskCount(ctx context.Context) uint64 {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.TaskCountKey)
	bz := store.Get(byteKey)

	// Count doesn't exist: no element
	if bz == nil {
		return 0
	}

	// Parse bytes
	return binary.BigEndian.Uint64(bz)
}

// SetTaskCount set the total number of task
func (k Keeper) SetTaskCount(ctx context.Context, count uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.TaskCountKey)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, count)
	store.Set(byteKey, bz)
}

// AppendTask appends a task in the store with a new id and update the count
func (k Keeper) AppendTask(
	ctx context.Context,
	task types.Task,
) uint64 {
	// Create the task
	count := k.GetTaskCount(ctx)

	// Set the ID of the appended value
	task.Id = count

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.TaskKey))
	appendedValue := k.cdc.MustMarshal(&task)
	store.Set(GetTaskIDBytes(task.Id), appendedValue)

	// Update task count
	k.SetTaskCount(ctx, count+1)

	return count
}

// SetTask set a specific task in the store
func (k Keeper) SetTask(ctx context.Context, task types.Task) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.TaskKey))
	b := k.cdc.MustMarshal(&task)
	store.Set(GetTaskIDBytes(task.Id), b)
}

// GetTask returns a task from its id
func (k Keeper) GetTask(ctx context.Context, id uint64) (val types.Task, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.TaskKey))
	b := store.Get(GetTaskIDBytes(id))
	if b == nil {
		return val, false
	}
	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveTask removes a task from the store
func (k Keeper) RemoveTask(ctx context.Context, id uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.TaskKey))
	store.Delete(GetTaskIDBytes(id))
}

// GetAllTask returns all task
func (k Keeper) GetAllTask(ctx context.Context) (list []types.Task) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.TaskKey))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Task
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}

// GetTaskIDBytes returns the byte representation of the ID
func GetTaskIDBytes(id uint64) []byte {
	bz := types.KeyPrefix(types.TaskKey)
	bz = append(bz, []byte("/")...)
	bz = binary.BigEndian.AppendUint64(bz, id)
	return bz
}
