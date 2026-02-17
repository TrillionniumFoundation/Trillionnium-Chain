package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "chain/testutil/keeper"
	"chain/testutil/nullify"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNWorker(keeper keeper.Keeper, ctx context.Context, n int) []types.Worker {
	items := make([]types.Worker, n)
	for i := range items {
		items[i].Creator = strconv.Itoa(i)

		keeper.SetWorker(ctx, items[i])
	}
	return items
}

func TestWorkerGet(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNWorker(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetWorker(ctx,
			item.Creator,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestWorkerRemove(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNWorker(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveWorker(ctx,
			item.Creator,
		)
		_, found := keeper.GetWorker(ctx,
			item.Creator,
		)
		require.False(t, found)
	}
}

func TestWorkerGetAll(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNWorker(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllWorker(ctx)),
	)
}
