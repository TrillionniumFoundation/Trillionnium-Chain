package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "chain/testutil/keeper"
	"chain/x/workload/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.WorkloadKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
