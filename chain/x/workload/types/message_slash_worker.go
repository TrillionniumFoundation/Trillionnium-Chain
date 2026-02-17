package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSlashWorker{}

func NewMsgSlashWorker(creator string, worker string, slashPercent uint64) *MsgSlashWorker {
	return &MsgSlashWorker{
		Creator:      creator,
		Worker:       worker,
		SlashPercent: slashPercent,
	}
}

func (msg *MsgSlashWorker) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
