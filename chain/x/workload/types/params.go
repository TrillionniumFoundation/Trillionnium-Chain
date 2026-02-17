package types

import (
	"fmt"

	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
)

var _ paramtypes.ParamSet = (*Params)(nil)

// ParamKeyTable the param key table for launch module
func ParamKeyTable() paramtypes.KeyTable {
	return paramtypes.NewKeyTable().RegisterParamSet(&Params{})
}

var (
	KeyWorkloadDenom = []byte("WorkloadDenom")
)

// NewParams creates a new Params instance
func NewParams(workloadDenom string) Params {
	return Params{WorkloadDenom: workloadDenom}
}

// DefaultParams returns a default set of parameters
func DefaultParams() Params {
	return NewParams("utrnm")
}

// ParamSetPairs get the params.ParamSet
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(KeyWorkloadDenom, &p.WorkloadDenom, validateWorkloadDenom),
	}
}

func validateWorkloadDenom(i interface{}) error {
	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	if v == "" {
		return fmt.Errorf("workload denom cannot be empty")
	}
	return nil
}

// Validate validates the set of params
func (p Params) Validate() error {
	return validateWorkloadDenom(p.WorkloadDenom)
}
