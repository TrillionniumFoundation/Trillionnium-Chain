package keeper

import (
	"context"
	"encoding/binary"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// GetChallengeCount get the total number of challenge
func (k Keeper) GetChallengeCount(ctx context.Context) uint64 {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.ChallengeCountKey)
	bz := store.Get(byteKey)
	if bz == nil {
		return 0
	}
	return binary.BigEndian.Uint64(bz)
}

// SetChallengeCount set the total number of challenge
func (k Keeper) SetChallengeCount(ctx context.Context, count uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, []byte{})
	byteKey := types.KeyPrefix(types.ChallengeCountKey)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, count)
	store.Set(byteKey, bz)
}

// AppendChallenge appends a challenge in the store with a new id and update the count
func (k Keeper) AppendChallenge(ctx context.Context, challenge types.Challenge) uint64 {
	count := k.GetChallengeCount(ctx)
	challenge.Id = count

	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ChallengeKey))
	appendedValue := k.cdc.MustMarshal(&challenge)
	store.Set(GetChallengeIDBytes(challenge.Id), appendedValue)

	k.SetChallengeCount(ctx, count+1)
	return count
}

// SetChallenge set a specific challenge in the store
func (k Keeper) SetChallenge(ctx context.Context, challenge types.Challenge) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ChallengeKey))
	b := k.cdc.MustMarshal(&challenge)
	store.Set(GetChallengeIDBytes(challenge.Id), b)
}

// GetChallenge returns a challenge from its id
func (k Keeper) GetChallenge(ctx context.Context, id uint64) (val types.Challenge, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ChallengeKey))
	b := store.Get(GetChallengeIDBytes(id))
	if b == nil {
		return val, false
	}
	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveChallenge removes a challenge from the store
func (k Keeper) RemoveChallenge(ctx context.Context, id uint64) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ChallengeKey))
	store.Delete(GetChallengeIDBytes(id))
}

// GetAllChallenge returns all challenge
func (k Keeper) GetAllChallenge(ctx context.Context) (list []types.Challenge) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ChallengeKey))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.Challenge
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}
	return
}

// GetChallengeIDBytes returns the byte representation of the ID
func GetChallengeIDBytes(id uint64) []byte {
	bz := types.KeyPrefix(types.ChallengeKey)
	bz = append(bz, []byte("/")...)
	bz = binary.BigEndian.AppendUint64(bz, id)
	return bz
}
