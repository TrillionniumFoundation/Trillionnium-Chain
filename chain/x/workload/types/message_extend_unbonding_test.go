package types

import (
	"testing"

	"chain/testutil/sample"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgExtendUnbonding_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgExtendUnbonding
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgExtendUnbonding{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgExtendUnbonding{
				Creator: sample.AccAddress(),
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
