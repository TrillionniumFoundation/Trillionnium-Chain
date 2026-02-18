package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) ChallengeAll(ctx context.Context, req *types.QueryAllChallengeRequest) (*types.QueryAllChallengeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var challenges []types.Challenge

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	challengeStore := prefix.NewStore(store, types.KeyPrefix(types.ChallengeKey))

	pageRes, err := query.Paginate(challengeStore, req.Pagination, func(key []byte, value []byte) error {
		var challenge types.Challenge
		if err := k.cdc.Unmarshal(value, &challenge); err != nil {
			return err
		}
		challenges = append(challenges, challenge)
		return nil
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllChallengeResponse{Challenge: challenges, Pagination: pageRes}, nil
}

func (k Keeper) Challenge(ctx context.Context, req *types.QueryGetChallengeRequest) (*types.QueryGetChallengeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	challenge, found := k.GetChallenge(ctx, req.Id)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound
	}

	return &types.QueryGetChallengeResponse{Challenge: challenge}, nil
}
