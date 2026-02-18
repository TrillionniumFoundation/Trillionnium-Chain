package keeper_test

import (
	"context"
	"testing"

	keepertest "chain/testutil/keeper"
	"chain/testutil/nullify"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	"github.com/stretchr/testify/require"
)

func createNChallenge(keeper keeper.Keeper, ctx context.Context, n int) []types.Challenge {
	items := make([]types.Challenge, n)
	for i := range items {
		items[i].Id = keeper.AppendChallenge(ctx, items[i])
	}
	return items
}

func TestChallengeGet(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNChallenge(keeper, ctx, 10)
	for _, item := range items {
		got, found := keeper.GetChallenge(ctx, item.Id)
		require.True(t, found)
		require.Equal(t, nullify.Fill(&item), nullify.Fill(&got))
	}
}

func TestChallengeRemove(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNChallenge(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveChallenge(ctx, item.Id)
		_, found := keeper.GetChallenge(ctx, item.Id)
		require.False(t, found)
	}
}

func TestChallengeGetAll(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNChallenge(keeper, ctx, 10)
	require.ElementsMatch(t, nullify.Fill(items), nullify.Fill(keeper.GetAllChallenge(ctx)))
}

func TestChallengeCount(t *testing.T) {
	keeper, ctx := keepertest.WorkloadKeeper(t)
	items := createNChallenge(keeper, ctx, 10)
	require.Equal(t, uint64(len(items)), keeper.GetChallengeCount(ctx))
}
