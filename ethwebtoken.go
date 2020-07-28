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
	EWTPrefix = "eth"

	EWTDomainVersion = "1"
)

var eip712Domain = ethcoder.TypedDataDomain{
	Name:    "ETHWebToken",
	Version: EWTDomainVersion,
}

func New(validators ...ValidatorFunc) (*ETHWebToken, error) {
	ewt := &ETHWebToken{validators: validators}
	if len(ewt.validators) == 0 {
		ewt.validators = []ValidatorFunc{ValidateEOAToken, ValidateContractAccountToken}
	}
	return ewt, nil
}

func (w *ETHWebToken) ConfigJsonRpcProvider(ethereumJsonRpcURL string) error {
	var err error

	w.provider, err = ethrpc.NewProvider(ethereumJsonRpcURL)
	if err != nil {
		return err
	}

	chainID, err := w.provider.ChainID(context.Background())
	if err != nil {
		return err
	}
	w.chainID = chainID

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

func (w *ETHWebToken) EncodeToken(address string, claims Claims, signature string) (*Token, string, error) {
	if address == "" || len(address) != 42 || address[0:2] != "0x" {
		return nil, "", fmt.Errorf("ethwebtoken: invalid address")
	}
	if err := claims.Valid(); err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: invalid claims, %w", err)
	}
	if signature == "" || signature[0:2] != "0x" {
		return nil, "", fmt.Errorf("ethwebtoken: signature")
	}

	// Create token object
	token, err := newToken(address, claims, signature)
	if err != nil {
		return nil, "", err
	}

	// Validate token signature and claims
	valid, err := w.ValidateTokenSignature(token)
	if !valid || err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: token signature is invalid - %w", err)
	}

	valid, err = w.ValidateTokenClaims(token)
	if !valid || err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: token claims are invalid - %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: cannot marshal token claims - %w", err)
	}

	// Encode the token string
	var tokenb bytes.Buffer

	// prefix
	tokenb.WriteString(EWTPrefix)
	tokenb.WriteString(".")

	// address
	tokenb.WriteString(strings.ToLower(address))
	tokenb.WriteString(".")

	// message base64 encoded
	tokenb.WriteString(Base64UrlEncode(claimsJSON))
	tokenb.WriteString(".")

	// signature
	tokenb.WriteString(signature)

	// record the encoded token string on the Token object
	token.tokenString = tokenb.String()

	return token, token.String(), nil
}

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
	token, err := newToken(address, claims, signature)
	if err != nil {
		return false, nil, err
	}
	token.tokenString = tokenString

	// Validate token signature and claims
	valid, err := w.ValidateTokenSignature(token)
	if !valid || err != nil {
		return false, token, fmt.Errorf("ethwebtoken: token signature is invalid - %w", err)
	}

	valid, err = w.ValidateTokenClaims(token)
	if !valid || err != nil {
		return false, token, fmt.Errorf("ethwebtoken: token claims are invalid - %w", err)
	}

	return true, token, nil
}

func (w *ETHWebToken) ValidateTokenSignature(token *Token) (bool, error) {
	for _, v := range w.validators {
		isValid, _, err := v(context.Background(), w.provider, w.chainID, token)
		if !isValid || err != nil {
			return false, err
		}
		if isValid {
			return true, nil
		}
	}
	return false, nil
}

func (w *ETHWebToken) ValidateTokenClaims(token *Token) (bool, error) {
	err := token.Claims().Valid()
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
