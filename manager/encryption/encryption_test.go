package encryption

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	// not providing an encoder/decoder will just use the noop encoder/decoder
	msg := []byte("hello swarmkit")
	encoded, err := Encode(msg, nil)
	require.NoError(t, err)
	decoded, err := Decode(encoded, nil)
	require.NoError(t, err)
	require.Equal(t, msg, decoded)

	// the default encoder can produce something the default decoder can read
	encoder, decoder := GetDefaults([]byte("key"))
	encoded, err = Encode(msg, encoder)
	require.NoError(t, err)
	decoded, err = Decode(encoded, decoder)
	require.NoError(t, err)
	require.Equal(t, msg, decoded)

	// mismatched encoders and decoders can't read the content produced by each
	encoded, err = Encode(msg, nil)
	require.NoError(t, err)
	_, err = Decode(encoded, decoder)
	require.Error(t, err)
	require.IsType(t, ErrCannotDecode{}, err)

	encoded, err = Encode(msg, encoder)
	require.NoError(t, err)
	_, err = Decode(encoded, nil)
	require.Error(t, err)
	require.IsType(t, ErrCannotDecode{}, err)
}
