package ethwebtoken

import (
	"github.com/pkg/errors"
)

type ETHWebToken struct {
	// Account addres
	Address string

	// Messaged passed to the ethSignedTypedData
	Payload string

	// Signature of the message by the account address above
	Proof string
}

func (t *ETHWebToken) Encode() (string, error) {
	if t.Address == "" || len(t.Address) != 42 || t.Address[0:2] != "0x" {
		return "", errors.Errorf("ethwebtoken: invalid address")
	}
	if t.Payload == "" {
		return "", errors.Errorf("ethwebtoken: invalid payload")
	}
	if t.Proof == "" {
		return "", errors.Errorf("ethwebtoken: invalid signature")
	}

	//...

	return "", nil
}

func ParseETHWebToken(token string) (*ETHWebToken, error) {

	return nil, nil
}
