package ethwebtoken

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/pkg/errors"
)

const (
	ewtPrefix = "eth"
)

type ETHWebToken struct {
	// "eth" prefix
	prefix string

	// Account addres
	address string

	// Messaged passed to the ethSignedTypedData
	payload string

	// Signature of the message by the account address above
	proof string
}

func (t *ETHWebToken) Address() string {
	return t.address
}

func (t *ETHWebToken) Payload() string {
	return t.payload
}

func (t *ETHWebToken) Proof() string {
	return t.proof
}

func (t *ETHWebToken) IsValid() (bool, error) {
	if t.prefix != ewtPrefix {
		return false, errors.Errorf("ethwebtoken: validation failed, invalid prefix")
	}
	if len(t.address) != 42 || t.address[0:2] != "0x" {
		return false, errors.Errorf("ethwebtoken: validation failed, invalid address")
	}
	if len(t.payload) == 0 {
		return false, errors.Errorf("ethwebtoken: validation failed, invalid payload")
	}
	if len(t.proof) < 2 || t.proof[0:2] != "0x" {
		return false, errors.Errorf("ethwebtoken: validation failed, invalid proof")
	}
	return ValidateETHSignature(t.address, t.payload, t.proof)
}

func (t *ETHWebToken) Encode() (string, error) {
	if t.address == "" || len(t.address) != 42 || t.address[0:2] != "0x" {
		return "", errors.Errorf("ethwebtoken: invalid address")
	}
	if t.payload == "" {
		return "", errors.Errorf("ethwebtoken: invalid payload")
	}
	if t.proof == "" || t.proof[0:2] != "0x" {
		return "", errors.Errorf("ethwebtoken: invalid proof")
	}

	// Validate the contents
	valid, err := ValidateETHSignature(t.address, t.payload, t.proof)
	if !valid || err != nil {
		return "", errors.Errorf("ethwebtoken: validation failed during encoding")
	}

	// TODO: add ValidatePayload()
	// and ensure we have basic contents for convensions of the subject, exp, iat, etc..

	var ewt bytes.Buffer

	// prefix
	ewt.WriteString(ewtPrefix)
	ewt.WriteString(".")

	// address
	ewt.WriteString(t.address)
	ewt.WriteString(".")

	// payload
	ewt.WriteString(base64.RawURLEncoding.EncodeToString([]byte(t.payload)))
	ewt.WriteString(".")

	// proof
	ewt.WriteString(t.proof)

	return ewt.String(), nil
}

func SignAndEncodeToken(address, payload string) (*ETHWebToken, string, error) {
	return nil, "", errors.Errorf("not implemented")
}

func EncodeToken(address, payload, proof string) (*ETHWebToken, string, error) {
	ewt := &ETHWebToken{
		prefix:  ewtPrefix,
		address: strings.ToLower(address),
		payload: payload,
		proof:   proof,
	}
	token, err := ewt.Encode()
	if err != nil {
		return nil, "", err
	}
	return ewt, token, nil
}

// DecodeToken will parse a ewt token string and validate its contents
func DecodeToken(token string) (bool, *ETHWebToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return false, nil, errors.Errorf("ethwebtoken: invalid token string")
	}

	prefix := parts[0]
	address := parts[1]
	payloadBase64 := parts[2]
	proof := parts[3]

	// decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return false, nil, errors.Errorf("ethwebtoken: decode failed, invalid payload")
	}

	ewt := &ETHWebToken{
		prefix: prefix, address: address, payload: string(payloadBytes), proof: proof,
	}
	isValid, err := ewt.IsValid()
	if !isValid || err != nil {
		return false, nil, errors.Errorf("ethwebtoken: decode failed, invalid token")
	}

	return true, ewt, nil
}
