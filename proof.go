package ethauth

import (
	"fmt"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
)

type Proof struct {
	// "eth" prefix
	Prefix string

	// Account addres (in hex)
	Address string

	// Claims object, aka, the message key of an EIP712 signature
	Claims Claims

	// Signature of the message by the account address above (in hex)
	Signature string

	// Extra bytes in hex format used for signature validation
	// ie. useful for counterfactual smart wallets
	Extra string
}

func NewProof() *Proof {
	return &Proof{
		Prefix: ETHAuthPrefix,
		Claims: Claims{
			ETHAuthVersion: ETHAuthVersion,
		},
	}
}

func (t *Proof) MessageDigest() ([]byte, error) {
	return t.Claims.MessageDigest()
}

func (t *Proof) MessageTypedData() (*ethcoder.TypedData, error) {
	return t.Claims.TypedData()
}

type Claims struct {
	App            string `json:"app,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ExpiresAt      int64  `json:"exp,omitempty"`
	Nonce          uint64 `json:"n,omitempty"`
	Type           string `json:"typ,omitempty"`
	Origin         string `json:"ogn,omitempty"`
	ETHAuthVersion string `json:"v,omitempty"`
}

func (c *Claims) SetIssuedAtNow() {
	c.IssuedAt = time.Now().UTC().Unix()
}

func (c *Claims) SetExpiryIn(tm time.Duration) {
	c.ExpiresAt = time.Now().UTC().Unix() + int64(tm.Seconds())
}

func (c Claims) Valid() error {
	now := time.Now().Unix()
	drift := int64(5 * 60)                                          // 5 minutes
	max := int64(time.Duration(time.Hour*24*365).Seconds()) + drift // 1 year

	if c.ETHAuthVersion == "" {
		return fmt.Errorf("claims: ethauth version is empty")
	}
	if c.App == "" {
		return fmt.Errorf("claims: app is empty")
	}
	if c.IssuedAt > now+drift {
		return fmt.Errorf("claims: proof is issued from the future - check if device clock is synced.")
	}
	if c.ExpiresAt < now-drift || c.ExpiresAt > now+max || c.IssuedAt < now-max {
		return fmt.Errorf("claims: proof has expired")
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
	if c.ETHAuthVersion != "" {
		m["v"] = c.ETHAuthVersion
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
		return nil, fmt.Errorf("ethauth: claims is empty")
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
	if c.ETHAuthVersion != "" {
		claimsType = append(claimsType, ethcoder.TypedDataArgument{Name: "v", Type: "string"})
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
		return nil, fmt.Errorf("ethauth: failed to compute claims typed data - %w", err)
	}

	digest, err := typedData.EncodeDigest()
	if err != nil {
		return nil, fmt.Errorf("ethauth: failed to compute claims message digest - %w", err)
	}

	return digest, nil
}
