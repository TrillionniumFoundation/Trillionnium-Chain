package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSubmitResult{}

func NewMsgSubmitResult(creator string, taskID uint64, resultHash, resultURI string) *MsgSubmitResult {
	return &MsgSubmitResult{
		Creator:    creator,
		TaskId:     taskID,
		ResultHash: resultHash,
		ResultUri:  resultURI,
	}
}

func (msg *MsgSubmitResult) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	if msg.ResultHash == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "result hash cannot be empty")
	}
	return nil
}

var _ sdk.Msg = &MsgChallengeResult{}

func NewMsgChallengeResult(creator string, taskID uint64, reason, evidenceURI string) *MsgChallengeResult {
	return &MsgChallengeResult{
		Creator:     creator,
		TaskId:      taskID,
		Reason:      reason,
		EvidenceUri: evidenceURI,
	}
}

func (msg *MsgChallengeResult) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgResolveChallenge{}

func NewMsgResolveChallenge(creator string, taskID uint64, challengeSucceeded bool, finalResultHash, memo string) *MsgResolveChallenge {
	return &MsgResolveChallenge{
		Creator:            creator,
		TaskId:             taskID,
		ChallengeSucceeded: challengeSucceeded,
		FinalResultHash:    finalResultHash,
		Memo:               memo,
	}
}

func (msg *MsgResolveChallenge) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
