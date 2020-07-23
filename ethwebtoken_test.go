package ethwebtoken

import (
	"strings"
	"testing"
	"time"

	"github.com/arcadeum/ethkit/ethcoder"
	"github.com/arcadeum/ethkit/ethwallet"
	"github.com/stretchr/testify/assert"
)

func TestClaims(t *testing.T) {
	claims := Claims{
		App:      "SkyWeaver",
		IssuedAt: time.Now().UTC().Unix(),
	}

	typedData, err := claims.TypedData()
	assert.NoError(t, err)

	_, err = typedData.EncodeDigest()
	assert.NoError(t, err)
}

func TestEncodeDecodeFromEOA(t *testing.T) {
	ewt, err := New()
	assert.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromRandomEntropy()
	assert.NoError(t, err)

	claims := Claims{
		App:       "EWTTest",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Unix() + int64(time.Duration(time.Minute*5).Seconds()),
	}
	assert.NoError(t, claims.Valid())

	// sign the message sub-digest
	messageDigest, err := claims.MessageDigest()
	assert.NoError(t, err)

	sig, err := wallet.SignMessage(messageDigest)
	assert.NoError(t, err)
	sigHex := ethcoder.HexEncode(sig)

	// encode the ewt
	token, tokenString, err := ewt.EncodeToken(wallet.Address().String(), claims, sigHex)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(tokenString, EWTPrefix))

	// decode the ewt
	ok, token, err := ewt.DecodeToken(tokenString)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, ewt)
	assert.Equal(t, strings.ToLower(wallet.Address().String()), token.Address())

	// fmt.Println("==> address", wallet.Address().String())
	// fmt.Println("==> tokenString", tokenString)
	// fmt.Println("==> claims", token.Claims().Map())
}

func TestTokenClaims(t *testing.T) {
	extraSecs := int64(10 * 60) // 10 minutes

	// valid claims
	{
		claims := Claims{
			App:       "TestTokenClaims",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.NoError(t, claims.Valid())

	}

	// invalid claims
	{
		// invalid -- issuedAt is in the future
		claims := Claims{
			App:       "TestTokenClaims",
			IssuedAt:  time.Now().Unix() + extraSecs,
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "iat")

		// invalid -- issuedAt is unset
		claims = Claims{
			App:       "TestTokenClaims",
			ExpiresAt: time.Now().Unix() + extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "iat")

		// invalid -- expiry is in the past
		claims = Claims{
			App:       "TestTokenClaims",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() - extraSecs,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")

		// invalid -- expiry is unset
		claims = Claims{
			App:      "TestTokenClaims",
			IssuedAt: time.Now().Unix(),
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")
	}

}
