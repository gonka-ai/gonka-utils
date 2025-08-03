package utils

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	ed "github.com/cometbft/cometbft/crypto/ed25519"
	cryptotypes "github.com/cometbft/cometbft/proto/tendermint/crypto"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/gogoproto/proto"
	ics23 "github.com/cosmos/ics23/go"
	"github.com/gonka-ai/gonka-utils/go/contracts"
)

const genesisBlockHeight = int64(1)

type (
	GetParticipantsFn = func(ctx context.Context, epoch string) (*contracts.ActiveParticipantWithProof, error)
	GetValidatorsFn   = func(ctx context.Context, height int64) (*contracts.BlockValidators, error)
	GetBlockFn        = func(ctx context.Context, height int64) (*coretypes.ResultBlock, error)
)

func VerifyParticipants(
	ctx context.Context, expectedAppHashHex string,
	getParticipants GetParticipantsFn,
	getValidatorsFn GetValidatorsFn,
	getBlockFn GetBlockFn) error {
	var validatorsNplus1 map[string]string
	resp, err := getParticipants(ctx, "current")
	if err != nil {
		return err
	}

	for epochId := resp.ActiveParticipants.EpochId; ; {
		validatorsNplus1, err = verifyParticipants(*resp, validatorsNplus1)
		if err != nil {
			return err
		}

		if resp.Block.AppHash.String() == expectedAppHashHex {
			return nil
		}

		epochId--
		if epochId == 0 {
			break
		}
		resp, err = getParticipants(ctx, fmt.Sprintf("%d", epochId))
		if err != nil {
			return err
		}
	}

	genesisBlock, err := getBlockFn(ctx, genesisBlockHeight)
	if err != nil {
		return err
	}

	if genesisBlock.Block.AppHash.String() != expectedAppHashHex {
		return fmt.Errorf("participants unverified: expected hash %s, but got %s", expectedAppHashHex, resp.Block.AppHash.String())
	}

	validators, err := getValidatorsFn(ctx, genesisBlockHeight)
	if err != nil {
		return err
	}

	genesisValidatorsData := make(map[string]struct{})
	for _, validator := range validators.Validators {
		genesisValidatorsData[validator.Address] = struct{}{}
	}

	for _, validator := range resp.Validators {
		_, ok := genesisValidatorsData[validator.Address]
		if !ok {
			fmt.Printf("validator %s not found in genesis block\n", validator.Address)
		}
	}
	return fmt.Errorf("participants unverified: expected hash %s, but got %s", expectedAppHashHex, resp.Block.AppHash.String())
}

func verifyParticipants(resp contracts.ActiveParticipantWithProof, validatorsNplus1 map[string]string) (map[string]string, error) {
	participantsN := make(map[string]struct{})
	for _, participant := range resp.ActiveParticipants.Participants {
		participantsN[participant.ValidatorKey] = struct{}{}
	}

	if len(validatorsNplus1) != 0 {
		for _, pubkey := range validatorsNplus1 {
			if _, ok := participantsN[pubkey]; !ok {
				return nil, errors.New("validator not found in previous epoch active participants set")
			}
		}
	}

	block := resp.Block
	value, err := hex.DecodeString(resp.ActiveParticipantsBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode active participants bytes : %w", err)
	}

	if err := VerifyIAVLProofAgainstAppHash(block.AppHash, resp.ProofOps.Ops, value); err != nil {
		return nil, err
	}

	vote := tmproto.Vote{
		Type:   tmproto.PrecommitType,
		Height: block.LastCommit.Height,
		Round:  block.LastCommit.Round,
		BlockID: tmproto.BlockID{
			Hash: block.LastCommit.BlockID.Hash,
			PartSetHeader: tmproto.PartSetHeader{
				Total: block.LastCommit.BlockID.PartSetHeader.Total,
				Hash:  block.LastCommit.BlockID.PartSetHeader.Hash,
			},
		},
	}

	validatorsData := make(map[string]string)
	for _, validator := range resp.Validators {
		validatorsData[validator.Address] = validator.PubKey
	}

	if err := VerifySignatures(vote, block.ChainID, validatorsData, block.LastCommit.Signatures); err != nil {
		return nil, err
	}

	return validatorsData, nil
}

// VerifyIAVLProofAgainstAppHash verifies the correctness of an ABCIQuery response for ActiveParticipants.
//
// In our case, ActiveParticipants always return proofOps consisting of exactly two items:
//  1. ics23:iavl   — proves that the key (active_participants_by_epoch) → value (active participants entities) is indeed present in the IAVL tree of the "inference" store;
//  2. ics23:simple — proves that the root of this store (storeRoot) is included in the block’s AppHash.
//
// Thanks to this fixed proof structure, we can implement a simpler verification function
// without dealing with a fully generic chain of nested Merkle proofs.
// The function:
//   - first verifies key → value in the IAVL store (and obtains storeRoot);
//   - then verifies that the storeRoot is included in the block’s AppHash;
//   - if both checks succeed, the value is guaranteed to be part of the application state
//     signed by validators at the given block height.
func VerifyIAVLProofAgainstAppHash(appHash []byte, proofOps []cryptotypes.ProofOp, value []byte) error {
	if len(proofOps) != 2 {
		return fmt.Errorf("expected 2 proof ops, got %d", len(proofOps))
	}

	// Step 1: key → value в store (IAVL)
	iavlOp := proofOps[0]
	if iavlOp.Type != "ics23:iavl" {
		return fmt.Errorf("unexpected first proof op type: %s", iavlOp.Type)
	}
	var iavlProof ics23.CommitmentProof
	if err := proto.Unmarshal(iavlOp.Data, &iavlProof); err != nil {
		return fmt.Errorf("failed to unmarshal IAVL proof: %w", err)
	}
	storeRoot, err := iavlProof.Calculate()
	if err != nil {
		return fmt.Errorf("failed to calculate IAVL proof: %w", err)
	}

	if ok := ics23.VerifyMembership(ics23.IavlSpec, storeRoot, &iavlProof, iavlOp.Key, value); !ok {
		return fmt.Errorf("IAVL proof failed")
	}

	// Step 2: storeRoot → AppHash (Tendermint multistore)
	simpleOp := proofOps[1]
	if simpleOp.Type != "ics23:simple" {
		return fmt.Errorf("unexpected second proof op type: %s", simpleOp.Type)
	}
	var simpleProof ics23.CommitmentProof
	if err := proto.Unmarshal(simpleOp.Data, &simpleProof); err != nil {
		return fmt.Errorf("failed to unmarshal simple proof: %w", err)
	}
	if ok := ics23.VerifyMembership(ics23.TendermintSpec, appHash, &simpleProof, simpleOp.Key, storeRoot); !ok {
		return fmt.Errorf("simple proof failed")
	}
	return nil
}

func VerifySignatures(vote tmproto.Vote, chainId string, validators map[string]string, signatures []tmtypes.CommitSig) error {
	for _, signature := range signatures {
		vote.Timestamp = signature.Timestamp
		signBytes := tmtypes.VoteSignBytes(chainId, &vote)

		pubKeyBase64 := validators[signature.ValidatorAddress.String()]
		pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
		if err != nil {
			return fmt.Errorf("decode pubkey: %w", err)
		}

		pubKey := ed.PubKey(pubKeyBytes)
		if ok := pubKey.VerifySignature(signBytes, signature.Signature); !ok {
			return fmt.Errorf("failed to verify signature for addr %v \n", pubKey.Address().String())
		}
	}
	return nil
}
