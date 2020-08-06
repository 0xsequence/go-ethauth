package ethwebtoken

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

type ValidatorFunc func(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, token *Token) (bool, string, error)

// ValidateEOAToken verifies the account proof of the provided ewt, testing if the
// token has been signed with an EOA (externally owned account) and will return
// success/failture, the account address as a string, and any errors.
func ValidateEOAToken(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, token *Token) (bool, string, error) {
	// Compute eip712 message digest from the token claims
	messageDigest, err := token.MessageDigest()
	if err != nil {
		return false, "", fmt.Errorf("ValidateEOAToken failed. Unable to compute token message digest, because %w", err)
	}

	isValid, err := ValidateEOASignature(token.Address, messageDigest, token.Signature)
	if err != nil {
		return false, "", err
	}
	if !isValid {
		return false, "", fmt.Errorf("ValidateEOAToken failed. invalid EOA signature")
	}
	return true, token.Address, nil
}

// ValidateContractAccountToken verifies the account proof of the provided ewt, testing if the
// token has been signed with a smart-contract based account by calling the EIP-1271
// method of the remote contract. This method will return success/failure, the
// account address as a string, and any errors.
func ValidateContractAccountToken(ctx context.Context, provider *ethrpc.Provider, chainID *big.Int, token *Token) (bool, string, error) {
	if provider == nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. provider is nil")
	}
	if chainID == nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. chainID is nil")
	}

	// Compute eip712 message digest from the token claims
	messageDigest, err := token.MessageDigest()
	if err != nil {
		return false, "", fmt.Errorf("ValidateEOAToken failed. Unable to compute token message digest, because %w", err)
	}

	// Early check to ensure the contract wallet has been deployed
	walletCode, err := provider.CodeAt(ctx, common.HexToAddress(token.Address), nil)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. unable to fetch wallet contract code - %w", err)
	}
	if len(walletCode) == 0 {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. unable to fetch wallet contract code, likely wallet has not been deployed")
	}

	// Call EIP-1271 IsValidSignature(bytes32, bytes) method on the deployed wallet. Note: for undeployed
	// wallets, you will need to implement your own ValidatorFunc with the additional context.
	signature, err := ethcoder.HexDecode(token.Signature)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. HexDecode of token.signature failed - %w", err)
	}

	input, err := ethcoder.AbiEncodeMethodCalldata("isValidSignature(bytes32,bytes)", []interface{}{
		ethcoder.BytesToBytes32(messageDigest),
		signature,
	})
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. EncodeMethodCalldata error")
	}

	toAddress := common.HexToAddress(token.Address)
	txMsg := ethereum.CallMsg{
		To:   &toAddress,
		Data: input,
	}

	output, err := provider.CallContract(context.Background(), txMsg, nil)
	if err != nil {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. Provider CallContract failed - %w", err)
	}

	isValid := len(output) >= 4 && IsValidSignatureBytes32 == ethcoder.HexEncode(output[:4])
	if !isValid {
		return false, "", fmt.Errorf("ValidateContractAccountToken failed. invalid signature")
	}
	return true, token.Address, nil
}

const (
	// IsValidSignatureBytes32 is the EIP-1271 magic value we test
	IsValidSignatureBytes32 = "0x1626ba7e"
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
