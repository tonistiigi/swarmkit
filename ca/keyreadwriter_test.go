package ca_test

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/swarmkit/ca"
	"github.com/stretchr/testify/require"
)

// can read and write tls keys that aren't encrypted, and that are encrypted
func TestKeyReadWriter(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	expectedKey := key

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir, "subdir")) // to make sure subdirectories are created

	checkCanReadWithKEK := func(kek []byte) *ca.KeyReadWriter {
		k := ca.NewKeyReadWriter(path.Node, kek, nil)
		readCert, readKey, err := k.Read()
		require.NoError(t, err)
		require.Equal(t, cert, readCert)
		require.Equal(t, expectedKey, readKey, "Expected %s, Got %s", string(expectedKey), string(readKey))
		return k
	}

	k := ca.NewKeyReadWriter(path.Node, nil, nil)

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
	k = ca.NewKeyReadWriter(path.Node, []byte("original kek"), nil)
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

// KeyReaderWriter makes a call to a header updater, if one is provided
func TestKeyReadWriterWithKeyHeaderUpdater(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	// write a key with headers to the key to make sure it gets overwritten
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	key = pem.EncodeToMemory(keyBlock)

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir, "subdir")) // to make sure subdirectories are created

	// if if getting new headers fail, writing a key fails, and the key does not rotate
	var count int
	k := ca.NewKeyReadWriter(path.Node, nil, func(map[string]string, []byte, []byte) error {
		if count == 0 {
			count++
			return fmt.Errorf("fail")
		}
		return nil
	})
	// first write will fail
	require.Error(t, k.Write(cert, key, &ca.KEKUpdate{KEK: []byte("failed kek")}))
	// second write will succeed, using the original kek (nil)
	require.NoError(t, k.Write(cert, key, nil))
	k = ca.NewKeyReadWriter(path.Node, nil, nil)
	_, _, err = k.Read()
	require.NoError(t, err)

	// writing new headers is called with existing headers, and will write a key that has the headers
	// returned by the header update function
	k = ca.NewKeyReadWriter(path.Node, []byte("oldKek"), func(headers map[string]string, oldKek []byte, newKek []byte) error {
		require.Equal(t, headers, map[string]string{"hello": "world"})
		require.Equal(t, []byte("oldKek"), oldKek)
		require.Equal(t, []byte("newKek"), newKek)
		delete(headers, "hello")
		headers["updated"] = "headers"
		return nil
	})
	require.NoError(t, k.Write(cert, key, &ca.KEKUpdate{KEK: []byte("newKek")}))

	// make sure headers were correctly set
	_, readKey, err := k.Read()
	require.NoError(t, err)
	keyBlock, _ = pem.Decode(readKey)
	require.NotNil(t, keyBlock)
	require.Equal(t, map[string]string{"updated": "headers"}, keyBlock.Headers)
}

func TestKeyReadWriterReadUpdateHeaders(t *testing.T) {
	_, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir))

	// write a key with headers to the key to make sure it gets passed when reading/writing headers
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	key = pem.EncodeToMemory(keyBlock)
	require.NoError(t, ioutil.WriteFile(path.Node.Key, key, 0600))

	// if the update headers callback function fails, updating headers fails
	k := ca.NewKeyReadWriter(path.Node, []byte("kek"), nil)
	err = k.UpdateHeaders(func(map[string]string, []byte) error {
		return fmt.Errorf("nope")
	})
	require.Error(t, err)
	require.Equal(t, "nope", err.Error())

	// updating headers succeed and is called with the latest kek
	err = k.UpdateHeaders(func(headers map[string]string, kek []byte) error {
		require.Equal(t, []byte("kek"), kek)
		require.Equal(t, keyBlock.Headers, headers)
		delete(headers, "hello")
		headers["updated"] = "headers"
		return nil
	})
	require.NoError(t, err)

	// reading headers returns the current headers and kek
	headers, kek, err := k.ReadHeaders()
	require.NoError(t, err)
	require.Equal(t, map[string]string{"updated": "headers"}, headers)
	require.Equal(t, []byte("kek"), kek)
}

func TestKeyReadWriterRotateKEK(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir))

	// write a key with headers to the key to make sure it gets passed when reading/writing headers
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	key = pem.EncodeToMemory(keyBlock)
	require.NoError(t, ca.NewKeyReadWriter(path.Node, nil, nil).Write(cert, key, nil))

	// if if getting new headers fail, rotating a KEK fails, and the kek does not rotate
	k := ca.NewKeyReadWriter(path.Node, nil, func(map[string]string, []byte, []byte) error {
		return fmt.Errorf("fail")
	})
	require.Error(t, k.RotateKEK([]byte("failed kek")))

	// writing new headers is called with existing headers, and will write a key that has the headers
	// returned by the header update function
	k = ca.NewKeyReadWriter(path.Node, []byte("oldKek"), func(headers map[string]string, oldKek []byte, newKek []byte) error {
		require.Equal(t, headers, map[string]string{"hello": "world"})
		require.Equal(t, []byte("oldKek"), oldKek)
		require.Equal(t, []byte("newKek"), newKek)
		delete(headers, "hello")
		headers["updated"] = "headers"
		return nil
	})
	require.NoError(t, k.RotateKEK([]byte("newKek")))

	// ensure the key has been re-encrypted and we can read it
	k = ca.NewKeyReadWriter(path.Node, nil, nil)
	_, _, err = k.Read()
	require.Error(t, err)

	k = ca.NewKeyReadWriter(path.Node, []byte("newKek"), nil)
	_, readKey, err := k.Read()
	require.NoError(t, err)
	keyBlock.Headers = map[string]string{"updated": "headers"}
	require.Equal(t, pem.EncodeToMemory(keyBlock), readKey)
}
