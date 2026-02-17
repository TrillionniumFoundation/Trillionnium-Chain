package types

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateWorkloadDenom(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr string
	}{
		{
			name:  "valid minimal length denom",
			input: "abc",
		},
		{
			name:  "valid max length denom",
			input: "a" + strings.Repeat("b", 127),
		},
		{
			name:    "invalid type",
			input:   int64(1),
			wantErr: "invalid parameter type",
		},
		{
			name:    "empty",
			input:   "",
			wantErr: "workload denom cannot be empty",
		},
		{
			name:    "too short",
			input:   "ab",
			wantErr: "invalid workload denom",
		},
		{
			name:    "starts with digit",
			input:   "1abc",
			wantErr: "invalid workload denom",
		},
		{
			name:    "contains whitespace",
			input:   "ab c",
			wantErr: "invalid workload denom",
		},
		{
			name:    "too long",
			input:   "a" + strings.Repeat("b", 128),
			wantErr: "invalid workload denom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWorkloadDenom(tc.input)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestParamsValidate_ErrorMessageContainsDenom(t *testing.T) {
	invalid := "1bad"
	err := NewParams(invalid).Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("invalid workload denom %q", invalid))
}
