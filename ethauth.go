package ethauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethrpc"
)

type ETHAuth struct {
	validators []ValidatorFunc

	ethereumJsonRpcURL string
	provider           *ethrpc.Provider
	chainID            *big.Int
}

const (
	ETHAuthVersion = "1"

	ETHAuthPrefix = "eth"
)

var eip712Domain = ethcoder.TypedDataDomain{
	Name:    "ETHAuth",
	Version: ETHAuthVersion,
}

func New(validators ...ValidatorFunc) (*ETHAuth, error) {
	ea := &ETHAuth{validators: validators}
	if len(ea.validators) == 0 {
		ea.validators = []ValidatorFunc{ValidateEOAProof, ValidateContractAccountProof}
	}
	err := ea.ConfigValidators(ea.validators...)
	if err != nil {
		return nil, err
	}
	return ea, nil
}

func (w *ETHAuth) ConfigJsonRpcProvider(ethereumJsonRpcURL string, optChainId ...int64) error {
	var err error

	w.provider, err = ethrpc.NewProvider(ethereumJsonRpcURL)
	if err != nil {
		return err
	}

	if len(optChainId) > 0 {
		w.chainID = big.NewInt(optChainId[0])
	} else {
		chainID, err := w.provider.ChainID(context.Background())
		if err != nil {
			return err
		}
		w.chainID = chainID
	}

	w.ethereumJsonRpcURL = ethereumJsonRpcURL
	return nil
}

func (w *ETHAuth) ConfigValidators(validators ...ValidatorFunc) error {
	if len(validators) == 0 {
		return fmt.Errorf("ethauth: validator list is empty")
	}
	w.validators = validators
	return nil
}

// EncodeProof will encode a Proof object, validate it and return the ETHAuth proof string
func (w *ETHAuth) EncodeProof(proof *Proof) (string, error) {
	if proof == nil {
		return "", fmt.Errorf("ethauth: proof is nil")
	}
	if proof.Address == "" || len(proof.Address) != 42 || proof.Address[0:2] != "0x" {
		return "", fmt.Errorf("ethauth: invalid address")
	}
	if proof.Signature == "" || proof.Signature[0:2] != "0x" {
		return "", fmt.Errorf("ethauth: signature")
	}
	if proof.Extra != "" && !strings.HasPrefix(proof.Extra, "0x") {
		return "", fmt.Errorf("ethauth: invalid extra encoding, expecting hex data")
	}

	// Validate proof signature and claims
	_, err := w.ValidateProof(proof)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(proof.Claims)
	if err != nil {
		return "", fmt.Errorf("ethauth: cannot marshal proof claims - %w", err)
	}

	// Encode the proof string
	var pb bytes.Buffer

	// prefix
	pb.WriteString(ETHAuthPrefix)
	pb.WriteString(".")

	// address
	pb.WriteString(strings.ToLower(proof.Address))
	pb.WriteString(".")

	// message base64 encoded
	pb.WriteString(Base64UrlEncode(claimsJSON))
	pb.WriteString(".")

	// signature
	pb.WriteString(proof.Signature)

	// extra
	if proof.Extra != "" {
		pb.WriteString(".")
		pb.WriteString(proof.Extra)
	}

	return pb.String(), nil
}

// DecodeProof will decode an ETHAuth proof string, validate it, and return a Proof object
func (w *ETHAuth) DecodeProof(proofString string) (bool, *Proof, error) {
	parts := strings.Split(proofString, ".")
	if len(parts) < 4 || len(parts) > 5 {
		return false, nil, fmt.Errorf("ethauth: invalid proof string")
	}

	prefix := parts[0]
	address := parts[1]
	messageBase64 := parts[2]
	signature := parts[3]
	extra := ""
	if len(parts) == 5 {
		extra = parts[4]
	}

	// check prefix
	if prefix != ETHAuthPrefix {
		return false, nil, fmt.Errorf("ethauth: not an ethauth proof")
	}

	// decode message base64
	messageBytes, err := Base64UrlDecode(messageBase64)
	if err != nil {
		return false, nil, fmt.Errorf("ethauth: decoding failed, invalid claims")
	}

	var claims Claims
	err = json.Unmarshal(messageBytes, &claims)
	if err != nil {
		return false, nil, fmt.Errorf("ethauth: decoding failed, cannot unmarshal claims")
	}

	// prepare proof
	proof := NewProof()
	proof.Prefix = prefix
	proof.Address = address
	proof.Claims = claims
	proof.Signature = signature
	proof.Extra = extra

	// Validate proof signature and claims
	_, err = w.ValidateProof(proof)
	if err != nil {
		return false, proof, err
	}

	return true, proof, nil
}

func (w *ETHAuth) ValidateProof(proof *Proof) (bool, error) {
	valid, err := w.ValidateProofClaims(proof)
	if !valid || err != nil {
		return false, fmt.Errorf("ethauth: proof claims are invalid - %w", err)
	}
	valid = w.ValidateProofSignature(proof)
	if !valid {
		return false, fmt.Errorf("ethauth: proof signature is invalid")
	}
	return true, nil
}

func (w *ETHAuth) ValidateProofSignature(proof *Proof) bool {
	retIsValid := make([]bool, len(w.validators))

	for i, v := range w.validators {
		isValid, _, _ := v(context.Background(), w.provider, w.chainID, proof)
		retIsValid[i] = isValid
		if isValid {
			// preemptively return true if we've determined it to be valid
			return true
		}
	}

	// Valid if one of the validators says so
	for _, isValid := range retIsValid {
		if isValid {
			return true
		}
	}
	return false
}

func (w *ETHAuth) ValidateProofClaims(proof *Proof) (bool, error) {
	err := proof.Claims.Valid()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (w *ETHAuth) Validators() []ValidatorFunc {
	return w.validators
}

// Base64 url-variant encoding with padding stripped.
// Note, this is the same encoding format as JWT.
func Base64UrlEncode(s []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}

// Base64 url-variant decoding with padding stripped.
// Note, this is the same encoding format as JWT.
func Base64UrlDecode(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(s)
}
