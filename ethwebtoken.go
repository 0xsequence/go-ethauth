package ethwebtoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

func New() (*ETHWebToken, error) {
	ewt := &ETHWebToken{
		validators: []ValidatorFunc{ValidateEOAToken},
	}
	return ewt, nil
}

type ETHWebToken struct {
	validators []ValidatorFunc
}

func (w *ETHWebToken) ConfigValidators(validators ...ValidatorFunc) error {
	if len(validators) == 0 {
		return fmt.Errorf("ethwebtoken: validator list is empty")
	}
	w.validators = validators
	return nil
}

func (w *ETHWebToken) EncodeToken(address, message, signature string) (*Token, string, error) {
	if address == "" || len(address) != 42 || address[0:2] != "0x" {
		return nil, "", fmt.Errorf("ethwebtoken: invalid address")
	}
	if message == "" || len(message) < 2 {
		return nil, "", fmt.Errorf("ethwebtoken: invalid message")
	}
	if signature == "" || signature[0:2] != "0x" {
		return nil, "", fmt.Errorf("ethwebtoken: signature")
	}

	// Create token object
	token, err := newToken(address, message, signature)
	if err != nil {
		return nil, "", err
	}

	// Validate token signature and claims
	valid, err := w.ValidateTokenSignature(token)
	if !valid || err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: token signature is invalid")
	}

	valid, err = w.ValidateTokenClaims(token)
	if !valid || err != nil {
		return nil, "", fmt.Errorf("ethwebtoken: token claims are invalid - %w", err)
	}

	// Encode the token string
	var tokenb bytes.Buffer

	// prefix
	tokenb.WriteString(ewtPrefix)
	tokenb.WriteString(".")

	// address
	tokenb.WriteString(strings.ToLower(address))
	tokenb.WriteString(".")

	// message base64 encoded
	tokenb.WriteString(base64.RawURLEncoding.EncodeToString([]byte(message)))
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
	if prefix != ewtPrefix {
		return false, nil, fmt.Errorf("ethwebtoken: not an ewt token")
	}

	// decode message base64
	messageBytes, err := base64.RawURLEncoding.DecodeString(messageBase64)
	if err != nil {
		return false, nil, fmt.Errorf("ethwebtoken: decoding failed, invalid message")
	}

	// prepare  token
	token, err := newToken(address, string(messageBytes), signature)
	if err != nil {
		return false, nil, err
	}
	token.tokenString = tokenString

	// Validate token signature and claims
	valid, err := w.ValidateTokenSignature(token)
	if !valid || err != nil {
		return false, token, fmt.Errorf("ethwebtoken: token signature is invalid")
	}

	valid, err = w.ValidateTokenClaims(token)
	if !valid || err != nil {
		return false, token, fmt.Errorf("ethwebtoken: token claims are invalid - %w", err)
	}

	return true, token, nil
}

func (w *ETHWebToken) ValidateTokenSignature(token *Token) (bool, error) {
	for _, v := range w.validators {
		isValid, _, _ := v(context.Background(), token)
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

const (
	ewtPrefix = "eth"
)
