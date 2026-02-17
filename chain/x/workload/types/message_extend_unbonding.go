package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgExtendUnbonding{}

func NewMsgExtendUnbonding(creator string, worker string, extraBlocks uint64) *MsgExtendUnbonding {
	return &MsgExtendUnbonding{
		Creator:     creator,
		Worker:      worker,
		ExtraBlocks: extraBlocks,
	}
}

func (msg *MsgExtendUnbonding) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
