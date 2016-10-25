package encryption

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/docker/swarmkit/api"
	"github.com/stretchr/testify/require"
)

// Using the same key to encrypt the same message, this encoder produces two
// different ciphertexts because it produces two different nonces.  Both
// of these can be decrypted into the same data though.
func TestNaclSecretbox(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	coder := NewNACLSecretbox(key)
	data := []byte("Hello world")

	er1, err := coder.Encode(data)
	require.NoError(t, err)

	er2, err := coder.Encode(data)
	require.NoError(t, err)

	require.NotEqual(t, er1.Data, er2.Data)
	require.NotEmpty(t, er1.Nonce, er2.Nonce)

	result, err := coder.Decode(*er1)
	require.NoError(t, err)
	require.Equal(t, data, result)

	result, err = coder.Decode(*er2)
	require.NoError(t, err)
	require.Equal(t, data, result)
}

func TestNaclSecretboxInvalidAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	coder := NewNACLSecretbox(key)
	er, err := coder.Encode([]byte("Hello world"))
	require.NoError(t, err)
	er.Algorithm = api.NotEncrypted

	_, err = coder.Decode(*er)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a NACL secretbox")
}

func TestNaclSecretboxCannotDecryptWithoutRightKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	coder := NewNACLSecretbox(key)
	er, err := coder.Encode([]byte("Hello world"))
	require.NoError(t, err)

	coder = NewNACLSecretbox([]byte{})
	_, err = coder.Decode(*er)
	require.Error(t, err)
}
