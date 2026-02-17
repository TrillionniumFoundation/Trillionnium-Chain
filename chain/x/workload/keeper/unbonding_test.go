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

func createNUnbonding(keeper keeper.Keeper, ctx context.Context, n int) []types.Unbonding {
	items := make([]types.Unbonding, n)
	for i := range items {
		items[i].Creator = strconv.Itoa(i)

		keeper.SetUnbonding(ctx, items[i])
	}
	return items
}

func TestUnbondingGet(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNUnbonding(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetUnbonding(ctx,
			item.Creator,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestUnbondingRemove(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNUnbonding(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveUnbonding(ctx,
			item.Creator,
		)
		_, found := keeper.GetUnbonding(ctx,
			item.Creator,
		)
		require.False(t, found)
	}
}

func TestUnbondingGetAll(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNUnbonding(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllUnbonding(ctx)),
	)
}
