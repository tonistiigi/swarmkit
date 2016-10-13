package storage

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/stretchr/testify/require"
)

// Saving a snapshot with a new key rotates the key, so that future items will be saved with the new key
func TestRaftLoggerSaveSnapWithNewKey(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "raft-storage")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	ctx := context.Background()

	logger := EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key1"),
	}
	_, err = logger.BootstrapNew(&api.RaftMember{})
	require.NoError(t, err)

	snapshot := fakeSnapshotData

	// everything should be saved with "key2" from here even though the initial key was "key1"
	err = logger.SaveSnapshot(snapshot, []byte("key2"))
	require.NoError(t, err)
	_, entries, _ := makeWALData(snapshot.Metadata.Index, snapshot.Metadata.Term)
	err = logger.SaveEntries(raftpb.HardState{}, entries)
	require.NoError(t, err)
	logger.Close(ctx)

	// now we can bootstrap from disk and ensure it is encrypted with "key2"
	logger = EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key2"),
	}
	results, err := logger.BootstrapFromDisk(ctx)
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Equal(t, snapshot, *results.Snapshot)
	require.Equal(t, entries, results.Entries)

	// saving without a new key saves with the previous key
	fakeSnapshotData.Metadata.Index += uint64(len(entries))
	fakeSnapshotData.Metadata.Term++
	_, entries, _ = makeWALData(snapshot.Metadata.Index, snapshot.Metadata.Term)
	err = logger.SaveSnapshot(snapshot, nil)
	require.NoError(t, err)
	err = logger.SaveEntries(raftpb.HardState{}, entries)
	require.NoError(t, err)
	logger.Close(ctx)

	// bootstrap from disk again ensure it is still encrypted with "key2"
	logger = EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key2"),
	}
	results, err = logger.BootstrapFromDisk(ctx)
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Equal(t, snapshot, *results.Snapshot)
	require.Equal(t, entries, results.Entries)
	logger.Close(ctx)
}

func TestBootstrapFromDisk(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "raft-storage")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	logger := EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key1"),
	}
	_, err = logger.BootstrapNew(&api.RaftMember{})
	require.NoError(t, err)

	// everything should be saved with "key1"
	_, entries, _ := makeWALData(0, 0)
	err = logger.SaveEntries(raftpb.HardState{}, entries)
	require.NoError(t, err)
	logger.Close(context.Background())

	// now we can bootstrap from disk, even if there is no snapshot
	logger = EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key1"),
	}
	results, err := logger.BootstrapFromDisk(context.Background())
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Nil(t, results.Snapshot)
	require.Equal(t, entries, results.Entries)

	// save a snapshot
	snapshot := fakeSnapshotData
	err = logger.SaveSnapshot(snapshot, logger.EncryptionKey)
	require.NoError(t, err)
	_, entries, _ = makeWALData(snapshot.Metadata.Index, snapshot.Metadata.Term)
	err = logger.SaveEntries(raftpb.HardState{}, entries)
	require.NoError(t, err)
	logger.Close(context.Background())

	// load snapshots and wals
	logger = EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key1"),
	}
	results, err = logger.BootstrapFromDisk(context.Background())
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Equal(t, snapshot, *results.Snapshot)
	require.Equal(t, entries, results.Entries)
}

// Ensure that we can change encoding and not have a race condition
func TestRaftLoggerRace(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "raft-storage")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	logger := EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("Hello"),
	}
	_, err = logger.BootstrapNew(&api.RaftMember{})
	require.NoError(t, err)

	_, entries, _ := makeWALData(fakeSnapshotData.Metadata.Index, fakeSnapshotData.Metadata.Term)

	done1 := make(chan error)
	done2 := make(chan error)
	done3 := make(chan error)
	go func() {
		done1 <- logger.SaveSnapshot(fakeSnapshotData, nil)
	}()
	go func() {
		done2 <- logger.SaveEntries(raftpb.HardState{}, entries)
	}()
	go func() {
		done3 <- logger.SaveSnapshot(fakeSnapshotData, []byte("Hello 2"))
	}()

	err = <-done1
	require.NoError(t, err, "unable to save snapshot")

	err = <-done2
	require.NoError(t, err, "unable to save entries")

	err = <-done3
	require.NoError(t, err, "unable to rotate key")
}

func TestMigrateWAL(t *testing.T) {
	t.Parallel()

	tempdir, err := ioutil.TempDir("", "raft-storage")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	// write some data
	logger := EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key"),
	}
	_, err = logger.BootstrapNew(&api.RaftMember{})
	require.NoError(t, err)

	snapshot := fakeSnapshotData

	err = logger.SaveSnapshot(snapshot, nil)
	require.NoError(t, err)
	_, entries, _ := makeWALData(snapshot.Metadata.Index, snapshot.Metadata.Term)
	err = logger.SaveEntries(raftpb.HardState{}, entries)
	require.NoError(t, err)
	logger.Close(context.Background())

	encoder, decoders := encryption.GetDefaults([]byte("key"))

	// Move and re-encode the WAL and snap directory so it looks like it was created by an old version
	walDir := filepath.Join(tempdir, "wal-v3")
	snapDir := filepath.Join(tempdir, "snap-v3")
	require.NoError(t, MigrateWALs(
		walDir, filepath.Join(tempdir, "wal"),
		NewWALFactory(encoder, decoders), OriginalWAL,
		walpb.Snapshot{Index: snapshot.Metadata.Index, Term: snapshot.Metadata.Term},
		nil,
	))
	require.NoError(t, MigrateSnapshot(
		snapDir, filepath.Join(tempdir, "snap"),
		NewSnapFactory(encoder, decoders), OriginalSnap,
	))
	require.NoError(t, os.RemoveAll(walDir))
	require.NoError(t, os.RemoveAll(snapDir))

	// Now bootstrap from disk and check that everything gets migrated
	logger = EncryptedRaftLogger{
		StateDir:      tempdir,
		EncryptionKey: []byte("key"),
	}
	results, err := logger.BootstrapFromDisk(context.Background())
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Equal(t, snapshot, *results.Snapshot)
	require.Equal(t, entries, results.Entries)

	_, err = os.Stat(walDir)
	require.NoError(t, err)

	_, err = os.Stat(snapDir)
	require.NoError(t, err)
}
