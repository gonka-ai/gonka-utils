package contracts

import (
	"time"

	cryptotypes "github.com/cometbft/cometbft/proto/tendermint/crypto"
)

type ActiveParticipantWithProof struct {
	ActiveParticipants      ActiveParticipants    `json:"active_participants"`
	Addresses               []string              `json:"addresses"`
	ActiveParticipantsBytes string                `json:"active_participants_bytes"`
	ProofOps                *cryptotypes.ProofOps `json:"proof_ops"`
	BlockProof              *BlockProof           `json:"block_proof"`
	ValidatorsProof         *ValidatorsProof      `json:"validators_proof"`
	ChainId                 string                `json:"chain_id"`
}

type ValidatorsProof struct {
	BlockHeight int64            `json:"block_height,omitempty"`
	Round       int64            `json:"round,omitempty"`
	BlockId     *BlockID         `json:"block_id,omitempty"`
	Signatures  []*SignatureInfo `json:"signatures,omitempty"`
}

type BlockID struct {
	Hash               string `json:"hash,omitempty"`
	PartSetHeaderTotal int64  `json:"part_set_header_total,omitempty"`
	PartSetHeaderHash  string `json:"part_set_header_hash,omitempty"`
}

type SignatureInfo struct {
	SignatureBase64     string    `json:"signature_base64,omitempty"`
	ValidatorAddressHex string    `json:"validator_address_hex,omitempty"`
	Timestamp           time.Time `json:"timestamp"`
}

type BlockProof struct {
	CreatedAtBlockHeight int64         `json:"created_at_block_height,omitempty"`
	AppHashHex           string        `json:"app_hash_hex,omitempty"`
	TotalVotingPower     int64         `json:"total_voting_power,omitempty"`
	Commits              []*CommitInfo `json:"commits,omitempty"`
}

type CommitInfo struct {
	ValidatorAddress string `json:"validator_address,omitempty"`
	ValidatorPubKey  string `json:"validator_pub_key,omitempty"`
	VotingPower      int64  `json:"voting_power,omitempty"`
}

type ActiveParticipants struct {
	Participants         []*ActiveParticipant `protobuf:"bytes,1,rep,name=participants,proto3" json:"participants,omitempty"`
	EpochGroupId         uint64               `protobuf:"varint,2,opt,name=epoch_group_id,json=epochGroupId,proto3" json:"epoch_group_id,omitempty"`
	PocStartBlockHeight  int64                `protobuf:"varint,3,opt,name=poc_start_block_height,json=pocStartBlockHeight,proto3" json:"poc_start_block_height,omitempty"`
	EffectiveBlockHeight int64                `protobuf:"varint,4,opt,name=effective_block_height,json=effectiveBlockHeight,proto3" json:"effective_block_height,omitempty"`
	CreatedAtBlockHeight int64                `protobuf:"varint,5,opt,name=created_at_block_height,json=createdAtBlockHeight,proto3" json:"created_at_block_height,omitempty"`
	EpochId              uint64               `protobuf:"varint,6,opt,name=epoch_id,json=epochId,proto3" json:"epoch_id,omitempty"`
}

type ActiveParticipant struct {
	Index        string          `json:"index,omitempty"`
	ValidatorKey string          `json:"validator_key,omitempty"`
	Weight       int64           `json:"weight,omitempty"`
	InferenceUrl string          `json:"inference_url,omitempty"`
	Models       []string        `json:"models,omitempty"`
	Seed         *RandomSeed     `json:"seed,omitempty"`
	MlNodes      []*ModelMLNodes `json:"ml_nodes,omitempty"`
}

type RandomSeed struct {
	Participant string `json:"participant,omitempty"`
	EpochIndex  uint64 `json:"epoch_index,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

type ModelMLNodes struct {
	MlNodes []*MLNodeInfo `json:"ml_nodes,omitempty"`
}

type MLNodeInfo struct {
	NodeId             string `json:"node_id,omitempty"`
	Throughput         int64  `json:"throughput,omitempty"`
	PocWeight          int64  `json:"poc_weight,omitempty"`
	TimeslotAllocation []bool `json:"timeslot_allocation,omitempty"`
}
