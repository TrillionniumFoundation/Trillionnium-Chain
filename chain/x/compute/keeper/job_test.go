package keeper_test

import (
	"context"
	"testing"

	keepertest "chain/testutil/keeper"
	"chain/x/compute/keeper"
	"chain/x/compute/types"
	"github.com/stretchr/testify/require"
)

func createNJob(keeper keeper.Keeper, ctx context.Context, n int) []types.Job {
	items := make([]types.Job, n)
	for i := range items {
		items[i].Creator = "any"
		items[i].Id = keeper.AppendJob(ctx, items[i])
	}
	return items
}

func TestJobGet(t *testing.T) {
	k, _, ctx := keepertest.ComputeKeeperWithWorkload(t)
	items := createNJob(k, ctx, 10)
	for _, item := range items {
		got, found := k.GetJob(ctx, item.Id)
		require.True(t, found)
		require.Equal(t, item, got)
	}
}

func TestJobRemove(t *testing.T) {
	k, _, ctx := keepertest.ComputeKeeperWithWorkload(t)
	items := createNJob(k, ctx, 10)
	for _, item := range items {
		k.RemoveJob(ctx, item.Id)
		_, found := k.GetJob(ctx, item.Id)
		require.False(t, found)
	}
}

func TestJobGetAll(t *testing.T) {
	k, _, ctx := keepertest.ComputeKeeperWithWorkload(t)
	items := createNJob(k, ctx, 10)
	require.ElementsMatch(t, items, k.GetAllJob(ctx))
}

func TestJobCount(t *testing.T) {
	k, _, ctx := keepertest.ComputeKeeperWithWorkload(t)
	items := createNJob(k, ctx, 10)
	count := uint64(len(items))
	require.Equal(t, count, k.GetJobCount(ctx))
}
