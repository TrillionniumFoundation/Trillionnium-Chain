package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateComputeJob{}

func NewMsgCreateComputeJob(creator string, payload string, requirements string) *MsgCreateComputeJob {
	return &MsgCreateComputeJob{
		Creator:      creator,
		Payload:      payload,
		Requirements: requirements,
	}
}

func (msg *MsgCreateComputeJob) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if msg.Payload == "" {
		return errorsmod.Wrap(ErrInvalidPayload, "payload cannot be empty")
	}
	return nil
}
