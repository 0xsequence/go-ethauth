package ethwebtoken

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeToken(t *testing.T) {
	address := "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
	payload := "Please sign this message!"
	proof := "0x0a390122d3c539f45f76b918a8211d3bf928443589871ad4ecbd7c5e1ea39f3b7dae1238ed784b03da2f0dc3e3def70d45796c5dba0bd580e407207f129bfbd71c"

	ewt, token, err := EncodeToken(address, payload, proof)
	assert.NoError(t, err)
	assert.NotNil(t, ewt)
	assert.NotEmpty(t, token)

	ok, ewt, err := DecodeToken(token)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, ewt)

	assert.Equal(t, strings.ToLower(address), ewt.Address())
}
