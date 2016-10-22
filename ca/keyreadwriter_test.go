package ca_test

import (
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/swarmkit/ca"
	"github.com/stretchr/testify/require"
)

// can read and write tls keys that aren't encrypted, and that are encrypted
func TestKeyReadWriterBasic(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	expectedKey := key

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir, "subdir")) // to make sure subdirectories are created

	checkCanReadWithKEK := func(kek []byte) *ca.KeyReadWriter {
		k := ca.NewKeyReadWriter(path.Node, kek)
		readCert, readKey, err := k.Read()
		require.NoError(t, err)
		require.Equal(t, cert, readCert)
		require.Equal(t, expectedKey, readKey, "Expected %s, Got %s", string(expectedKey), string(readKey))
		return k
	}

	k := ca.NewKeyReadWriter(path.Node, nil)

	// can't read things that don't exist
	_, _, err = k.Read()
	require.Error(t, err)

	// can write an unencrypted key
	require.NoError(t, k.Write(cert, key, nil))

	// can read unencrypted
	k = checkCanReadWithKEK(nil)

	// write a key with headers to the key to make sure they're preserved
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	expectedKey = pem.EncodeToMemory(keyBlock)
	require.NoError(t, ioutil.WriteFile(path.Node.Key, expectedKey, 0600))

	// if a kek is provided, we can still read unencrypted keys
	k = checkCanReadWithKEK([]byte("original kek"))

	// we can update the kek and write at the same time
	require.NoError(t, k.Write(cert, key, &ca.KEKUpdate{KEK: []byte("new kek!")}))
	// the same kek can still read, and will continue to write with this key if
	// no further kek updates are provided
	_, _, err = k.Read()
	require.NoError(t, err)
	require.NoError(t, k.Write(cert, key, nil))

	// without the right kek, we can't read
	k = ca.NewKeyReadWriter(path.Node, []byte("original kek"))
	_, _, err = k.Read()
	require.Error(t, err)

	// same new key, just for sanity
	k = checkCanReadWithKEK([]byte("new kek!"))

	// we can also change the kek back to nil, which means the key is unencrypted
	require.NoError(t, k.Write(cert, key, &ca.KEKUpdate{KEK: nil}))
	checkCanReadWithKEK(nil)

	// just read the key from disk and ensure that it's unencrypted, for sanity
	keyBytes, err := ioutil.ReadFile(path.Node.Key)
	require.NoError(t, err)
	require.Equal(t, expectedKey, keyBytes)
}
