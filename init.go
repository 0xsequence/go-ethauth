package ethwebtoken

import "github.com/arcadeum/ethkit/ethcoder"

const (
	EWTPrefix = "eth"

	EWTDomainVersion = "1"
)

var eip712Domain = ethcoder.TypedDataDomain{
	Name:    "ETHWebToken",
	Version: EWTDomainVersion,
}
