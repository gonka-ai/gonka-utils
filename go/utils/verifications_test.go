package utils

import (
	"github.com/gonka-ai/gonka-utils/go/contracts"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestVerifySignatures(t *testing.T) {
	const chainID = "gonka-mainnet"

	t1, err := time.Parse(time.RFC3339Nano, "2025-08-23T12:04:16.634850393Z")
	require.NoError(t, err)

	t2, err := time.Parse(time.RFC3339Nano, "2025-08-23T12:04:16.601168243Z")
	require.NoError(t, err)

	proof := contracts.ValidatorsProof{
		BlockHeight: 17665,
		Round:       0,
		BlockId: &contracts.BlockID{
			Hash:               "0B902548DF9480890973D4F085AED92D7A5D64E132BE4FCFD76EB472973170C2",
			PartSetHeaderTotal: 1,
			PartSetHeaderHash:  "78AAB0B9F08B50C5E7AE70C0376137A195F4AC1B08208E8B7F152779D25AB491",
		},
		Signatures: []*contracts.SignatureInfo{
			{
				SignatureBase64:     "LDIifb8QUyz3koJ6674F5iZ0WfJWmLTxCth/BJKp4auRH8hGeOz6MfPy+DERfQz6+AQzj/caPqImiAOIQArqBw==",
				ValidatorAddressHex: "13CCD46D7FF3BB4945A2FBC450A948B5A1C89EB9",
				Timestamp:           t1,
			},
			{
				SignatureBase64:     "SHfLV0c8r4ikqjwZ+xcopW0DOei0ARufdSymlVtYvlSd0SXRv9+uVfJ14dUT74HPh4hryeTisPy3cw7dXASbBw==",
				ValidatorAddressHex: "DF04B29653F664BDAC7DE851D52BDD5C8E205822",
				Timestamp:           t2,
			},
		},
	}

	// address hex -> pubkey (base64)
	validators := ValidatorsInfo{
		"13CCD46D7FF3BB4945A2FBC450A948B5A1C89EB9": "LLqBxOz+vD3p7sQsdEhBfrFH2QFMjy3fMasB9yBGSqs=",
		"DF04B29653F664BDAC7DE851D52BDD5C8E205822": "5QYFI0kdyBPrcld3FfOwoZdynfwN5li0qUbg3zwFK4I=",
	}

	err = VerifySignatures(proof, chainID, validators)
	require.NoError(t, err)
}
