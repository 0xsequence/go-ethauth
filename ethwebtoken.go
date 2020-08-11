package ethwebtoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/arcadeum/ethkit/ethcoder"
	"github.com/arcadeum/ethkit/ethrpc"
)

type ETHWebToken struct {
	validators []ValidatorFunc

	ethereumJsonRpcURL string
	provider           *ethrpc.Provider
	chainID            *big.Int
}

const (
	EWTVersion = "1"

	EWTPrefix = "eth"
)

var eip712Domain = ethcoder.TypedDataDomain{
	Name:    "ETHWebToken",
	Version: EWTVersion,
}

func New(validators ...ValidatorFunc) (*ETHWebToken, error) {
	ewt := &ETHWebToken{validators: validators}
	if len(ewt.validators) == 0 {
		ewt.validators = []ValidatorFunc{ValidateEOAToken, ValidateContractAccountToken}
	}
	err := ewt.ConfigValidators(ewt.validators...)
	if err != nil {
		return nil, err
	}
	return ewt, nil
}

func (w *ETHWebToken) ConfigJsonRpcProvider(ethereumJsonRpcURL string, optChainId ...int64) error {
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

func (w *ETHWebToken) ConfigValidators(validators ...ValidatorFunc) error {
	if len(validators) == 0 {
		return fmt.Errorf("ethwebtoken: validator list is empty")
	}
	w.validators = validators
	return nil
}

// EncodeToken will encode a Token object and return the EWT token string
func (w *ETHWebToken) EncodeToken(token *Token) (string, error) {
	if token == nil {
		return "", fmt.Errorf("ethwebtoken: token is nil")
	}
	if token.Address == "" || len(token.Address) != 42 || token.Address[0:2] != "0x" {
		return "", fmt.Errorf("ethwebtoken: invalid address")
	}
	if token.Signature == "" || token.Signature[0:2] != "0x" {
		return "", fmt.Errorf("ethwebtoken: signature")
	}

	// Validate token signature and claims
	_, err := w.ValidateToken(token)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(token.Claims)
	if err != nil {
		return "", fmt.Errorf("ethwebtoken: cannot marshal token claims - %w", err)
	}

	// Encode the token string
	var tokenb bytes.Buffer

	// prefix
	tokenb.WriteString(EWTPrefix)
	tokenb.WriteString(".")

	// address
	tokenb.WriteString(strings.ToLower(token.Address))
	tokenb.WriteString(".")

	// message base64 encoded
	tokenb.WriteString(Base64UrlEncode(claimsJSON))
	tokenb.WriteString(".")

	// signature
	tokenb.WriteString(token.Signature)

	return tokenb.String(), nil
}

// DecodeToken will decode an EWT token string and return a Token object
func (w *ETHWebToken) DecodeToken(tokenString string) (bool, *Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 4 {
		return false, nil, fmt.Errorf("ethwebtoken: invalid token string")
	}

	prefix := parts[0]
	address := parts[1]
	messageBase64 := parts[2]
	signature := parts[3]

	// check prefix
	if prefix != EWTPrefix {
		return false, nil, fmt.Errorf("ethwebtoken: not an ewt token")
	}

	// decode message base64
	messageBytes, err := Base64UrlDecode(messageBase64)
	if err != nil {
		return false, nil, fmt.Errorf("ethwebtoken: decoding failed, invalid claims")
	}

	var claims Claims
	err = json.Unmarshal(messageBytes, &claims)
	if err != nil {
		return false, nil, fmt.Errorf("ethwebtoken: decoding failed, cannot unmarshal claims")
	}

	// prepare  token
	token := NewToken()
	token.Prefix = prefix
	token.Address = address
	token.Claims = claims
	token.Signature = signature

	// Validate token signature and claims
	_, err = w.ValidateToken(token)
	if err != nil {
		return false, token, err
	}

	return true, token, nil
}

func (w *ETHWebToken) ValidateToken(token *Token) (bool, error) {
	valid, err := w.ValidateTokenClaims(token)
	if !valid || err != nil {
		return false, fmt.Errorf("ethwebtoken: token claims are invalid - %w", err)
	}
	valid = w.ValidateTokenSignature(token)
	if !valid {
		return false, fmt.Errorf("ethwebtoken: token signature is invalid")
	}
	return true, nil
}

func (w *ETHWebToken) ValidateTokenSignature(token *Token) bool {
	retIsValid := make([]bool, len(w.validators))

	for i, v := range w.validators {
		isValid, _, _ := v(context.Background(), w.provider, w.chainID, token)
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

func (w *ETHWebToken) ValidateTokenClaims(token *Token) (bool, error) {
	err := token.Claims.Valid()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (w *ETHWebToken) Validators() []ValidatorFunc {
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
