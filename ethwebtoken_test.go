package ethwebtoken

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arcadeum/ethkit/ethcoder"
	"github.com/arcadeum/ethkit/ethwallet"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeFromEOA(t *testing.T) {
	ewt, err := New()
	assert.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	assert.NoError(t, err)

	claims := Claims{
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Unix() + int64(time.Duration(time.Minute*5).Seconds()),
	}
	assert.NoError(t, claims.Valid())

	msgBytes, _ := json.Marshal(claims)

	// sign the message
	sig, err := wallet.SignMessage(msgBytes)
	assert.NoError(t, err)
	hexSig := ethcoder.HexEncode(sig)

	// encode the ewt
	token, tokenString, err := ewt.EncodeToken(wallet.Address().String(), string(msgBytes), hexSig)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(tokenString, ewtPrefix))

	// decode the ewt
	ok, token, err := ewt.DecodeToken(tokenString)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, ewt)
	assert.Equal(t, strings.ToLower(wallet.Address().String()), token.Address())
}

func TestTokenClaims(t *testing.T) {
	extraSecs := int64(10 * 60) // 10 minutes

	// valid claims
	{
		claims := Claims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.NoError(t, claims.Valid())

	}

	// invalid claims
	{
		// invalid -- issuedAt is in the future
		claims := Claims{
			IssuedAt:  time.Now().Unix() + extraSecs,
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "iat")

		// invalid -- issuedAt is unset
		claims = Claims{
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "iat")

		// invalid -- expiry is in the past
		claims = Claims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() - extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")

		// invalid -- expiry is unset
		claims = Claims{
			IssuedAt: time.Now().Unix(),
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")
	}

}
