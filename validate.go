package ethauth

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/arcadeum/ethkit/ethcoder"
	"github.com/arcadeum/ethkit/ethrpc"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type ValidatorFunc func(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, proof *Proof) (bool, string, error)

// ValidateEOAProof verifies the account proof, testing if the proof claims have been signed with an
// EOA (externally owned account) and will return success/failture, the account address as a string, and any errors.
func ValidateEOAProof(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, proof *Proof) (bool, string, error) {
	// Compute eip712 message digest from the proof claims
	messageDigest, err := proof.MessageDigest()
	if err != nil {
		return false, "", fmt.Errorf("ValidateEOAProof failed. Unable to compute ethauth message digest, because %w", err)
	}

	isValid, err := ValidateEOASignature(proof.Address, messageDigest, proof.Signature)
	if err != nil {
		return false, "", err
	}
	if !isValid {
		return false, "", fmt.Errorf("ValidateEOAProof failed. invalid EOA signature")
	}
	return true, proof.Address, nil
}

// ValidateContractAccountProof verifies the account proof, testing if the
// proof claims have been signed with a smart-contract based account by calling the EIP-1271
// method of the remote contract. This method will return success/failure, the
// account address as a string, and any errors. The wallet contract must be deployed in
// order for this call to be successful. In order test an undeployed smart-wallet, you
// will have to implement your own custom validator method.
func ValidateContractAccountProof(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, proof *Proof) (bool, string, error) {
	if provider == nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. provider is nil")
	}
	if chainID == nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. chainID is nil")
	}

	// Compute eip712 message digest from the proof claims
	messageDigest, err := proof.MessageDigest()
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. Unable to compute ethauth message digest, because %w", err)
	}

	// Early check to ensure the contract wallet has been deployed
	walletCode, err := provider.CodeAt(ctx, common.HexToAddress(proof.Address), nil)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. unable to fetch wallet contract code - %w", err)
	}
	if len(walletCode) == 0 {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. unable to fetch wallet contract code, likely wallet has not been deployed")
	}

	// Call EIP-1271 IsValidSignature(bytes32, bytes) method on the deployed wallet. Note: for undeployed
	// wallets, you will need to implement your own ValidatorFunc with the additional context.
	signature, err := ethcoder.HexDecode(proof.Signature)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. HexDecode of proof.signature failed - %w", err)
	}

	// must hash the message as first argument to isValidSignature
	messageHash := ethcoder.Keccak256(messageDigest)

	input, err := ethcoder.AbiEncodeMethodCalldata("isValidSignature(bytes32,bytes)", []interface{}{
		ethcoder.BytesToBytes32(messageHash),
		signature,
	})
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. EncodeMethodCalldata error")
	}

	toAddress := common.HexToAddress(proof.Address)
	txMsg := ethereum.CallMsg{
		To:   &toAddress,
		Data: input,
	}

	output, err := provider.CallContract(context.Background(), txMsg, nil)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. Provider CallContract failed - %w", err)
	}

	isValid := len(output) >= 4 && IsValidSignatureBytes32MagicValue == ethcoder.HexEncode(output[:4])
	if !isValid {
		return false, "", fmt.Errorf("ValidateContractAccountProof failed. invalid signature")
	}
	return true, proof.Address, nil
}

const (
	// IsValidSignatureBytes32 is the EIP-1271 magic value we test
	IsValidSignatureBytes32MagicValue = "0x1626ba7e"
)

// Validate the public key address of an Ethereum signed message
func ValidateEOASignature(address string, message []byte, signatureHex string) (bool, error) {
	if !common.IsHexAddress(address) {
		return false, fmt.Errorf("ValidateEOASignature, address is not a valid Ethereum address")
	}
	if len(message) < 1 || len(signatureHex) < 1 {
		return false, fmt.Errorf("ValidateEOASignature, message and signature must not be empty")
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%v%s", len(message), message)
	sig, err := hexutil.Decode(signatureHex)
	if err != nil {
		return false, fmt.Errorf("ValidateEOASignature, signature is an invalid hex string")
	}
	if len(sig) != 65 {
		return false, fmt.Errorf("ValidateEOASignature, signature is not of proper length")
	}
	hash := crypto.Keccak256([]byte(msg))
	if sig[64] > 1 {
		sig[64] -= 27 // recovery ID
	}

	pubkey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false, err
	}
	key := crypto.PubkeyToAddress(*pubkey).Hex()
	if strings.ToLower(key) == strings.ToLower(address) {
		return true, nil
	}
	return false, fmt.Errorf("ValidateEOASignature, invalid signature")
}
