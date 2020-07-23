package ethwebtoken

import (
	"fmt"
	"strings"
	"time"

	"github.com/arcadeum/ethkit/ethcoder"
)

type Token struct {
	// "eth" prefix
	prefix string

	// Account addres
	address string

	// Claims object, aka, the message key of an EIP712 signature
	claims Claims

	// Signature of the message by the account address above
	signature string

	// TokenString is the actual ewt token
	tokenString string
}

func newToken(address string, claims Claims, signature string) (*Token, error) {
	token := &Token{
		prefix:    EWTPrefix,
		address:   strings.ToLower(address),
		claims:    claims,
		signature: signature,
	}
	return token, nil
}

func (t *Token) Address() string {
	return t.address
}

func (t *Token) Claims() Claims {
	return t.claims
}

func (t *Token) Signature() string {
	return t.signature
}

func (t *Token) MessageDigest() ([]byte, error) {
	return t.claims.MessageDigest()
}

func (t *Token) String() string {
	if t.tokenString == "" {
		return "<ethwebtoken: Token, unencoded>"
	} else {
		return t.tokenString
	}
}

type Claims struct {
	App       string `json:"app,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Nonce     uint64 `json:"n,omitempty"`
	Type      string `json:"typ,omitempty"`
	Origin    string `json:"ogn,omitempty"`
}

func (c Claims) Valid() error {
	now := time.Now().Unix()
	drift := int64(5 * 60)                                      // 5 minutes
	max := int64(time.Duration(time.Hour * 24 * 365).Seconds()) // 1 year

	if c.App == "" {
		return fmt.Errorf("claims: app is empty")
	}
	if c.IssuedAt > now+drift || c.IssuedAt < now-max {
		return fmt.Errorf("claims: iat is invalid")
	}
	if c.ExpiresAt < now-drift || c.ExpiresAt > now+max {
		return fmt.Errorf("claims: token has expired")
	}

	return nil
}

func (c Claims) Map() map[string]interface{} {
	m := map[string]interface{}{}
	if c.App != "" {
		m["app"] = c.App
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.Nonce != 0 {
		m["n"] = c.Nonce
	}
	if c.Type != "" {
		m["typ"] = c.Type
	}
	if c.Origin != "" {
		m["ogn"] = c.Origin
	}
	return m
}

func (c Claims) TypedData() (*ethcoder.TypedData, error) {
	td := &ethcoder.TypedData{
		Types: ethcoder.TypedDataTypes{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
			},
			"Claims": {},
		},
		PrimaryType: "Claims",
		Domain:      eip712Domain,
		Message:     c.Map(),
	}

	if len(td.Message) == 0 {
		return nil, fmt.Errorf("ethwebtoken: claims is empty")
	}

	claimsType := []ethcoder.TypedDataArgument{}
	if c.App != "" {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "app", Type: "string"})
	}
	if c.IssuedAt != 0 {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "iat", Type: "int64"})
	}
	if c.ExpiresAt != 0 {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "exp", Type: "int64"})
	}
	if c.Nonce != 0 {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "n", Type: "uint64"})
	}
	if c.Type != "" {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "typ", Type: "string"})
	}
	if c.Origin != "" {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "ogn", Type: "string"})
	}
	td.Types["Claims"] = claimsType

	return td, nil
}

func (c Claims) MessageDigest() ([]byte, error) {
	if err := c.Valid(); err != nil {
		return nil, fmt.Errorf("claims are invalid - %w", err)
	}

	typedData, err := c.TypedData()
	if err != nil {
		return nil, fmt.Errorf("ethwebtoken: failed to compute claims typed data - %w", err)
	}
	digest, err := typedData.EncodeDigest()
	if err != nil {
		return nil, fmt.Errorf("ethwebtoken: failed to compute claims message digest - %w", err)
	}
	return digest, nil
}
