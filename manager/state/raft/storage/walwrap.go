package storage

import (
	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/docker/swarmkit/manager/encryption"
)

// This package wraps the github.com/coreos/etcd/wal package, and encodes
// the bytes of whatever entry is passed to it, and decodes the bytes of
// whatever entry it reads.

// WAL is the interface presented by github.com/coreos/etcd/wal.WAL that we depend upon
type WAL interface {
	ReadAll() ([]byte, raftpb.HardState, []raftpb.Entry, error)
	ReleaseLockTo(index uint64) error
	Close() error
	Save(st raftpb.HardState, ents []raftpb.Entry) error
	SaveSnapshot(e walpb.Snapshot) error
}

// WALFactory provides an interface for the different ways to get a WAL object.
// For instance, the etcd/wal package itself provides this
type WALFactory interface {
	Create(dirpath string, metadata []byte) (WAL, error)
	Open(dirpath string, walsnap walpb.Snapshot) (WAL, error)
}

var _ WAL = &wrappedWAL{}
var _ WAL = &wal.WAL{}
var _ WALFactory = walCryptor{}

// wrappedWAL wraps a github.com/coreos/etcd/wal.WAL, and handles encoding/decoding
type wrappedWAL struct {
	*wal.WAL
	encoder encryption.Encoder
	decoder encryption.Decoder
}

// ReadAll wraps the wal.WAL.ReadAll() function, but it first checks to see if the
// metadata indicates that the entries are encoded, and if so, decodes them.
func (w *wrappedWAL) ReadAll() ([]byte, raftpb.HardState, []raftpb.Entry, error) {
	metadata, state, ents, err := w.WAL.ReadAll()
	if err != nil {
		return metadata, state, ents, err
	}
	for i, ent := range ents {
		ents[i].Data, err = encryption.Decode(ent.Data, w.decoder)
		if err != nil {
			return nil, raftpb.HardState{}, nil, err
		}
	}

	return metadata, state, ents, nil
}

// Save encodes the entry data (if an encoder is exists) before passing it onto the
// wrapped wal.WAL's Save function.
func (w *wrappedWAL) Save(st raftpb.HardState, ents []raftpb.Entry) error {
	var writeEnts []raftpb.Entry
	for _, ent := range ents {
		data, err := encryption.Encode(ent.Data, w.encoder)
		if err != nil {
			return err
		}
		writeEnts = append(writeEnts, raftpb.Entry{
			Index: ent.Index,
			Term:  ent.Term,
			Type:  ent.Type,
			Data:  data,
		})
	}

	return w.WAL.Save(st, writeEnts)
}

// walCryptor is an object that provides the same functions as `etcd/wal`
// and `etcd/snap` that we need to open a WAL object or Snapshotter object
type walCryptor struct {
	encoder encryption.Encoder
	decoder encryption.Decoder
}

// NewWALFactory returns an object that can be used to produce objects that
// will read from and write to encrypted WALs on disk.
func NewWALFactory(encoder encryption.Encoder, decoder encryption.Decoder) WALFactory {
	return walCryptor{
		encoder: encoder,
		decoder: decoder,
	}
}

// Create returns a new WAL object with the given encoders and decoders.
func (wc walCryptor) Create(dirpath string, metadata []byte) (WAL, error) {
	w, err := wal.Create(dirpath, metadata)
	if err != nil {
		return nil, err
	}
	return &wrappedWAL{
		WAL:     w,
		encoder: wc.encoder,
		decoder: wc.decoder,
	}, nil
}

// Open returns a new WAL object with the given encoders and decoders.
func (wc walCryptor) Open(dirpath string, snap walpb.Snapshot) (WAL, error) {
	w, err := wal.Open(dirpath, snap)
	if err != nil {
		return nil, err
	}
	return &wrappedWAL{
		WAL:     w,
		encoder: wc.encoder,
		decoder: wc.decoder,
	}, nil
}

type originalWAL struct{}

func (o originalWAL) Create(dirpath string, metadata []byte) (WAL, error) {
	return wal.Create(dirpath, metadata)
}
func (o originalWAL) Open(dirpath string, walsnap walpb.Snapshot) (WAL, error) {
	return wal.Open(dirpath, walsnap)
}

// OriginalWAL is the original `wal` package as an implemntation of the WALFactory interface
var OriginalWAL = originalWAL{}
