package types

import (
	"testing"

	"chain/testutil/sample"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgCreateComputeJob_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgCreateComputeJob
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgCreateComputeJob{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgCreateComputeJob{
				Creator: sample.AccAddress(),
				Payload: "ipfs://valid-payload",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}
