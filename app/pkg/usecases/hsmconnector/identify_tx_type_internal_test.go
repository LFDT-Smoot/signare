package hsmconnector

import (
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"

	"github.com/stretchr/testify/require"
)

// TestIdentifyTxTypeLabelsEveryTransactionType pins the label identifyTxType returns for each
// combination of fields. SignTx reports this label as the "txType" trace property even for the types it
// declines to sign, so a wrong label is a silently misleading trace rather than a failing request.
func TestIdentifyTxTypeLabelsEveryTransactionType(t *testing.T) {
	amount := entities.NewHexInt256(big.NewInt(1))

	tests := []struct {
		name      string
		input     SignTxInput
		want      string
		wantError bool
	}{
		{
			name:  "no gas fields is legacy",
			input: SignTxInput{},
			want:  entities.TransactionType0Legacy,
		},
		{
			name:  "gas price alone is legacy",
			input: SignTxInput{GasPrice: amount},
			want:  entities.TransactionType0Legacy,
		},
		{
			name:  "an empty access list alone is EIP-2930",
			input: SignTxInput{AccessList: AccessList{}},
			want:  entities.TransactionType1EIP2930,
		},
		{
			name:  "an access list with a gas price is EIP-2930",
			input: SignTxInput{GasPrice: amount, AccessList: AccessList{}},
			want:  entities.TransactionType1EIP2930,
		},
		{
			name:  "both EIP-1559 fees without an access list is EIP-1559",
			input: SignTxInput{MaxFeePerGas: amount, MaxPriorityFeePerGas: amount},
			want:  entities.TransactionType2EIP1559,
		},
		{
			name:  "both EIP-1559 fees with an access list is EIP-1559",
			input: SignTxInput{MaxFeePerGas: amount, MaxPriorityFeePerGas: amount, AccessList: AccessList{}},
			want:  entities.TransactionType2EIP1559,
		},
		{
			name:  "a blob gas fee is EIP-4844",
			input: SignTxInput{MaxFeePerBlobGas: amount},
			want:  entities.TransactionType3EIP4844,
		},
		{
			name:  "blob versioned hashes are EIP-4844",
			input: SignTxInput{BlobVersionedHashes: []entities.HexBytes32{{}}},
			want:  entities.TransactionType3EIP4844,
		},
		{
			name:  "an authorization list is EIP-7702, not EIP-4844",
			input: SignTxInput{AuthorizationList: AuthorizationList{}},
			want:  entities.TransactionType4EIP7702,
		},
		{
			name:      "only one of the two EIP-1559 fees is rejected",
			input:     SignTxInput{MaxFeePerGas: amount},
			wantError: true,
		},
		{
			name:      "a gas price alongside both EIP-1559 fees is rejected",
			input:     SignTxInput{GasPrice: amount, MaxFeePerGas: amount, MaxPriorityFeePerGas: amount},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifyTxType(tt.input)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
