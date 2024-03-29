package ethauth

import (
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethcoder"
	"github.com/0xsequence/ethkit/ethwallet"
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
	ethAuth, err := New()
	assert.NoError(t, err)

	wallet, err := ethwallet.NewWalletFromMnemonic("outdoor sentence roast truly flower surface power begin ocean silent debate funny")
	assert.NoError(t, err)

	// iat := time.Now().Unix()
	// exp := time.Now().Unix() + int64(time.Duration(time.Hour*24*365).Seconds()) //int64(time.Duration(time.Minute*5).Seconds())
	// fmt.Println("=> iat", iat)
	// fmt.Println("=> exp", exp)

	claims := Claims{
		App: "ETHAuthTest",
		// IssuedAt:   iat,
		// ExpiresAt:  exp,
		ETHAuthVersion: ETHAuthVersion,
	}
	claims.SetIssuedAtNow()
	claims.SetExpiryIn(time.Duration(5 * time.Minute))
	assert.NoError(t, claims.Valid())

	// sign the message sub-digest
	messageDigest, err := claims.MessageDigest()
	assert.NoError(t, err)

	// digestHex := ethcoder.HexEncode(messageDigest)
	// fmt.Println("=> digestHex", digestHex)

	sig, err := wallet.SignMessage(messageDigest)
	assert.NoError(t, err)
	sigHex := ethcoder.HexEncode(sig)

	// encode the proof
	proof := NewProof()
	proof.Address = wallet.Address().String()
	proof.Claims = claims
	proof.Signature = sigHex

	proofString, err := ethAuth.EncodeProof(proof)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(proofString, ETHAuthPrefix))

	// decode the proof
	ok, proof, err := ethAuth.DecodeProof(proofString)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, ethAuth)
	assert.Equal(t, strings.ToLower(wallet.Address().String()), proof.Address)

	// fmt.Println("==> address", wallet.Address().String())
	// fmt.Println("==> proofString", proofString)
	// fmt.Println("==> claims", proof.Claims().Map())
}

func TestProofClaims(t *testing.T) {
	extraSecs := int64(10 * 60) // 10 minutes

	// valid claims
	{
		claims := Claims{
			App:            "TestProofClaims",
			IssuedAt:       time.Now().Unix(),
			ExpiresAt:      time.Now().Unix() + extraSecs,
			ETHAuthVersion: ETHAuthVersion,
		}
		assert.NoError(t, claims.Valid())

	}

	// invalid claims
	{
		// invalid -- issuedAt is in the future
		claims := Claims{
			App:            "TestProofClaims",
			IssuedAt:       time.Now().Unix() + extraSecs,
			ExpiresAt:      time.Now().Unix() + extraSecs,
			ETHAuthVersion: ETHAuthVersion,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "from the future")

		// invalid -- expiry is in the past
		claims = Claims{
			App:            "TestProofClaims",
			IssuedAt:       time.Now().Unix(),
			ExpiresAt:      time.Now().Unix() - extraSecs,
			ETHAuthVersion: ETHAuthVersion,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")

		// invalid -- expiry is unset
		claims = Claims{
			App:            "TestProofClaims",
			IssuedAt:       time.Now().Unix(),
			ETHAuthVersion: ETHAuthVersion,
		}
		assert.Error(t, claims.Valid())
		assert.Contains(t, claims.Valid().Error(), "expired")
	}

}
