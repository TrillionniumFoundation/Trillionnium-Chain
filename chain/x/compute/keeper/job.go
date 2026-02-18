package keeper

import (
	"context"
	"encoding/binary"

	"chain/x/compute/types"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// GetJobCount get the total number of job
func (k Keeper) GetJobCount(ctx context.Context) uint64 {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.JobCountKey)
	bz := store.Get(byteKey)

	// Count doesn't exist: no element
	if bz == nil {
		return 0
	}

	// Parse bytes
	return binary.BigEndian.Uint64(bz)
}

// SetJobCount set the total number of job
func (k Keeper) SetJobCount(ctx context.Context, count uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.JobCountKey)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, count)
	store.Set(byteKey, bz)
}

// AppendJob appends a job in the store with a new id and update the count
func (k Keeper) AppendJob(
	ctx context.Context,
	job types.Job,
) uint64 {
	// Create the job
	count := k.GetJobCount(ctx)

	// Set the ID of the appended value
	job.Id = count

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JobKey))
	appendedValue := k.cdc.MustMarshal(&job)
	store.Set(GetJobIDBytes(job.Id), appendedValue)

	// Update job count
	k.SetJobCount(ctx, count+1)

	return count
}

// SetJob set a specific job in the store
func (k Keeper) SetJob(ctx context.Context, job types.Job) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JobKey))
	b := k.cdc.MustMarshal(&job)
	store.Set(GetJobIDBytes(job.Id), b)
}

// GetJob returns a job from its id
func (k Keeper) GetJob(ctx context.Context, id uint64) (val types.Job, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JobKey))
	b := store.Get(GetJobIDBytes(id))
	if b == nil {
		return val, false
	}
	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveJob removes a job from the store
func (k Keeper) RemoveJob(ctx context.Context, id uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JobKey))
	store.Delete(GetJobIDBytes(id))
}

// GetAllJob returns all job
func (k Keeper) GetAllJob(ctx context.Context) (list []types.Job) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.JobKey))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Job
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}

// GetJobIDBytes returns the byte representation of the ID
func GetJobIDBytes(id uint64) []byte {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	return bz
}
