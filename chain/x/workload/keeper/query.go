package keeper

import (
	"chain/x/workload/types"
)

var _ types.QueryServer = Keeper{}
