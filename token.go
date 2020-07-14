package ethwebtoken

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Token struct {
	// "eth" prefix
	prefix string

	// Account addres
	address string

	// Message to sign
	message string

	// Claims object, decoded from the message string
	claims Claims

	// Signature of the message by the account address above
	signature string

	// TokenString is the actual ewt token
	tokenString string
}

func newToken(address, message, signature string) (*Token, error) {
	token := &Token{
		prefix:    ewtPrefix,
		address:   strings.ToLower(address),
		message:   message,
		signature: signature,
	}

	err := json.Unmarshal([]byte(message), &token.claims)
	if err != nil {
		return nil, fmt.Errorf("ethwebtoken: invalid message claims, expecting json message")
	}

	return token, nil
}

func (t *Token) Address() string {
	return t.address
}

func (t *Token) Message() string {
	return t.message
}

func (t *Token) Claims() Claims {
	return t.claims
}

func (t *Token) Signature() string {
	return t.signature
}

func (t *Token) String() string {
	if t.tokenString == "" {
		return "<ethwebtoken: Token, unencoded>"
	} else {
		return t.tokenString
	}
}

type Claims struct {
	Typ       string `json:"typ,omitempty"`
	App       string `json:"app,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Nonce     int64  `json:"n,omitempty"`
}

func (c Claims) Valid() error {
	now := time.Now().Unix()
	drift := int64(5 * 60)                                      // 5 minutes
	max := int64(time.Duration(time.Hour * 24 * 365).Seconds()) // 1 year

	if c.IssuedAt > now+drift || c.IssuedAt < now-max {
		return fmt.Errorf("iat claim is invalid")
	}
	if c.ExpiresAt < now-drift || c.ExpiresAt > now+max {
		return fmt.Errorf("token has expired")
	}

	return nil
}
