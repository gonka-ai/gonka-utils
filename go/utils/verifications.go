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
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/gogoproto/proto"
	ics23 "github.com/cosmos/ics23/go"
	"github.com/gonka-ai/gonka-utils/go/contracts"
	"strings"
)

type (
	GetParticipantsFn = func(ctx context.Context, epoch string) (*contracts.ActiveParticipantWithProof, error)
	ValidatorsInfo    = map[string]*contracts.CommitInfo
)

var (
	ErrEmptyValidatorsProof   = errors.New("empty validators proof")
	ErrParticipantsUnverified = errors.New("participants unverified")
)

func VerifyParticipants(ctx context.Context, expectedAppHashHex string, getParticipants GetParticipantsFn, epoch string) error {
	var (
		validatorsNplus1                map[string]*contracts.CommitInfo
		totalvalidatorsPowerNplus1      int64
		totalVotedValidatorsPowerNplus1 int64
	)
	resp, err := getParticipants(ctx, epoch)
	if err != nil {
		return err
	}

	for epochId := int64(resp.ActiveParticipants.EpochId - 1); epochId >= 0; epochId-- {
		validatorsNplus1, totalvalidatorsPowerNplus1, totalVotedValidatorsPowerNplus1, err =
			verifyParticipants(*resp, validatorsNplus1, totalvalidatorsPowerNplus1, totalVotedValidatorsPowerNplus1)
		if err != nil {
			return err
		}

		if strings.ToUpper(resp.BlockProof.AppHashHex) == strings.ToUpper(expectedAppHashHex) {
			return nil
		}

		resp, err = getParticipants(ctx, fmt.Sprintf("%d", epochId))
		if err != nil {
			return err
		}
	}
	if strings.ToUpper(resp.BlockProof.AppHashHex) != strings.ToUpper(expectedAppHashHex) {
		return ErrParticipantsUnverified
	}
	return nil
}

func verifyParticipants(
	resp contracts.ActiveParticipantWithProof,
	validatorsNplus1 map[string]*contracts.CommitInfo,
	totalPowerNPlus1, totalVotedPowerNPlus1 int64) (map[string]*contracts.CommitInfo, int64, int64, error) {
	value, err := hex.DecodeString(resp.ActiveParticipantsBytes)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode active participants bytes : %w", err)
	}

	appHash, err := hex.DecodeString(resp.BlockProof.AppHashHex)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode active participants app hash hex : %w", err)
	}

	if resp.ProofOps != nil {
		if err := VerifyIAVLProofAgainstAppHash(resp.ActiveParticipants.CreatedAtBlockHeight, appHash, resp.ProofOps.Ops, value); err != nil {
			return nil, 0, 0, err
		}
	}

	if resp.ValidatorsProof == nil {
		return nil, 0, 0, ErrEmptyValidatorsProof
	}

	participantsN := make(map[string]struct{})
	for _, participant := range resp.ActiveParticipants.Participants {
		participantsN[participant.ValidatorKey] = struct{}{}
	}

	if len(validatorsNplus1) != 0 {
		for _, commit := range validatorsNplus1 {
			if _, ok := participantsN[commit.ValidatorPubKey]; !ok {
				totalVotedPowerNPlus1 = totalVotedPowerNPlus1 - commit.VotingPower
			}
		}
	}

	minPowerNeeded := totalPowerNPlus1 / 100 * 51

	if totalVotedPowerNPlus1 < minPowerNeeded {
		return nil, 0, 0, errors.New("not enough voting power")
	}

	validatorsData := make(map[string]*contracts.CommitInfo)
	for _, commit := range resp.BlockProof.Commits {
		validatorsData[strings.ToUpper(commit.ValidatorAddress)] = commit
	}

	if err := VerifySignatures(*resp.ValidatorsProof, resp.ChainId, validatorsData); err != nil {
		return nil, 0, 0, err
	}
	return validatorsData, resp.BlockProof.TotalPower, resp.BlockProof.TotalVotedPower, nil
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
func VerifyIAVLProofAgainstAppHash(height int64, appHash []byte, proofOps []cryptotypes.ProofOp, value []byte) error {
	if len(proofOps) != 2 {
		if height != 1 {
			return fmt.Errorf("expected 2 proof ops, got %d", len(proofOps))
		}
		return nil
	}

	// Step 1: key → value in store (IAVL)
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

func VerifySignatures(validatorsProof contracts.ValidatorsProof, chainId string, validators ValidatorsInfo) error {
	blockIdHash, err := hex.DecodeString(validatorsProof.BlockId.Hash)
	if err != nil {
		return fmt.Errorf("failed to decode validators block hash hex : %w", err)
	}

	partsHeaderHash, err := hex.DecodeString(validatorsProof.BlockId.PartSetHeaderHash)
	if err != nil {
		return fmt.Errorf("failed to decode validators block header hash hex : %w", err)
	}

	vote := tmproto.Vote{
		Type:   tmproto.PrecommitType,
		Height: validatorsProof.BlockHeight,
		Round:  int32(validatorsProof.Round),
		BlockID: tmproto.BlockID{
			Hash: blockIdHash,
			PartSetHeader: tmproto.PartSetHeader{
				Total: uint32(validatorsProof.BlockId.PartSetHeaderTotal),
				Hash:  partsHeaderHash,
			},
		},
	}

	uniqueSignatures := make(map[string]struct{})

	for _, signature := range validatorsProof.Signatures {
		if signature.SignatureBase64 == "" {
			// really seldom corner case, when empty signature is in the LastCommit block structure as here http://204.12.168.157:26657/block?height=565617
			continue
		}

		if _, ok := uniqueSignatures[signature.SignatureBase64]; ok {
			return errors.New("duplicated signature")
		}

		uniqueSignatures[signature.SignatureBase64] = struct{}{}
		vote.Timestamp = signature.Timestamp
		signBytes := tmtypes.VoteSignBytes(chainId, &vote)
		commit, ok := validators[signature.ValidatorAddressHex]
		if !ok {
			return fmt.Errorf("no pubkey known for validator %v", signature.ValidatorAddressHex)
		}

		pubKeyBytes, err := base64.StdEncoding.DecodeString(commit.ValidatorPubKey)
		if err != nil {
			return fmt.Errorf("decode pubkey: %w", err)
		}

		pubKey := ed.PubKey(pubKeyBytes)
		vote.ValidatorAddress = pubKey.Address().Bytes()

		decodedSign, err := base64.StdEncoding.DecodeString(signature.SignatureBase64)
		if err != nil {
			return fmt.Errorf("decode signature: %w", err)
		}
		if ok := pubKey.VerifySignature(signBytes, decodedSign); !ok {
			return fmt.Errorf("failed to verify signature for addr %v", pubKey.Address().String())
		}
	}
	return nil
}
