package ethwebtoken

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type ValidatorFunc func(ctx context.Context, oken *Token) (bool, string, error)

// ValidateEOAToken verifies the account proof of the provided ewt, testing if the
// token has been signed with an EOA (externally owned account) and will return
// success/failture, the account address as a string, and any errors.
func ValidateEOAToken(ctx context.Context, token *Token) (bool, string, error) {
	valid, err := ValidateEOASignature(token.address, token.message, token.signature)
	if err != nil {
		return false, "", err
	}
	if !valid {
		return false, "", fmt.Errorf("ethwebtoken: invalid EOA signature")
	}
	return true, token.Address(), nil
}

// Validate the public key address of an Ethereum signed message
func ValidateEOASignature(address, message, signature string) (bool, error) {
	if !common.IsHexAddress(address) {
		return false, fmt.Errorf("ethwebtoken: address is not a valid Ethereum address")
	}
	if len(message) < 1 || len(signature) < 1 {
		return false, fmt.Errorf("ethwebtoken: message and signature must not be empty")
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%v%v", len(message), message)
	sig, err := hexutil.Decode(signature)
	if err != nil {
		return false, fmt.Errorf("ethwebtoken: signature is an invalid hex string")
	}
	if len(sig) != 65 {
		return false, fmt.Errorf("ethwebtoken: signature is not of proper length")
	}
	hash := crypto.Keccak256([]byte(msg))
	sig[64] -= 27 // recovery ID

	pubkey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false, err
	}
	key := crypto.PubkeyToAddress(*pubkey).Hex()
	if strings.ToLower(key) == strings.ToLower(address) {
		return true, nil
	}
	return false, fmt.Errorf("ethwebtoken: invalid signature")
}
