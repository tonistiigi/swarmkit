package storage

import (
	"bytes"
	"fmt"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/manager/encryption"
)

// Common test utilities

type meowCoder struct {
	// only take encoding failures - decode failures can happen if the bytes
	// do not have a cat
	encodeFailures map[string]struct{}
}

func (m meowCoder) Encode(orig []byte) (*api.EncryptedRecord, error) {
	if _, ok := m.encodeFailures[string(orig)]; ok {
		return nil, fmt.Errorf("refusing to encode")
	}
	return &api.EncryptedRecord{
		Algorithm: m.Algorithm(),
		Data:      append(orig, []byte("🐱")...),
	}, nil
}

func (m meowCoder) Decode(orig api.EncryptedRecord) ([]byte, error) {
	if orig.Algorithm != m.Algorithm() || !bytes.HasSuffix(orig.Data, []byte("🐱")) {
		return nil, fmt.Errorf("not meowcoded")
	}
	return bytes.TrimSuffix(orig.Data, []byte("🐱")), nil
}

func (m meowCoder) Algorithm() api.EncryptedRecord_Algorithm {
	return api.EncryptedRecord_Algorithm(-1)
}

var _ encryption.Encoder = meowCoder{}
var _ encryption.Decoder = meowCoder{}
