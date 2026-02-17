package keeper

import (
	"chain/x/compute/types"
)

var _ types.QueryServer = Keeper{}
