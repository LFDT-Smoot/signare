package hsmconnector

import (
	"math/big"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/internal/errors"

	curves "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateBackendSignature(t *testing.T) {
	n := curves.S256().Params().N
	nMinusOne := new(big.Int).Sub(n, big.NewInt(1))

	// rs builds a 64-byte raw r||s signature from the given r and s values.
	rs := func(r, s *big.Int) []byte {
		out := make([]byte, backendSignatureLength)
		r.FillBytes(out[:backendSignatureLength/2])
		s.FillBytes(out[backendSignatureLength/2:])
		return out
	}

	t.Run("valid", func(t *testing.T) {
		validCases := map[string][]byte{
			"r=1, s=1":     rs(big.NewInt(1), big.NewInt(1)),
			"r=N-1, s=N-1": rs(nMinusOne, nMinusOne),
		}
		for name, sig := range validCases {
			t.Run(name, func(t *testing.T) {
				require.NoError(t, validateBackendSignature(sig))
			})
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		lengthCases := map[string]int{
			"empty":        0,
			"too short 63": 63,
			"too long 65":  65,
			"der-ish 70":   70,
		}
		for name, length := range lengthCases {
			t.Run(name, func(t *testing.T) {
				err := validateBackendSignature(make([]byte, length))
				require.Error(t, err)
				require.True(t, errors.IsBadGateway(err))
				require.Contains(t, err.Error(), "malformed signature")
			})
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		rangeCases := map[string][]byte{
			"s == 0": rs(big.NewInt(1), big.NewInt(0)),
			"r == 0": rs(big.NewInt(0), big.NewInt(1)),
			"s == N": rs(big.NewInt(1), n),
			"r == N": rs(n, big.NewInt(1)),
		}
		for name, sig := range rangeCases {
			t.Run(name, func(t *testing.T) {
				err := validateBackendSignature(sig)
				require.Error(t, err)
				require.True(t, errors.IsBadGateway(err))
				require.Contains(t, err.Error(), "malformed signature")
			})
		}
	})
}
