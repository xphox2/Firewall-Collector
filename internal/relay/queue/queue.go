// Package queue implements a two-tier FIFO queue: a small in-memory slice
// plus a BoltDB-backed spillover for durability. Items that exceed the
// in-memory cap are moved to BoltDB, where they are evicted oldest-first
// when the on-disk byte cap is reached.
//
// AUDIT-058: the four data queues in the relay package (traps, pings,
// syslog, flows) were pure-RAM slices; the goal of this package is to
// make them survive a process restart AND tolerate a multi-day central
// server outage.
package queue

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Config controls the on-disk + in-memory behavior of a SpilloverQueue.
type Config struct {
	// Path is the BoltDB file path. Created if missing; parent dirs are
	// created with mode 0o755.
	Path string
	// Bucket is the bbolt bucket name within the DB. Required.
	Bucket string
	// MaxMem is the max number of items held in RAM. Items past this spill
	// to disk (oldest first).
	MaxMem int
	// MaxBytes is the on-disk byte cap (sum of stored key+value bytes).
	// 0 disables byte-cap enforcement.
	MaxBytes int64
}

// SpilloverQueue is a two-tier FIFO queue backed by an in-memory slice and
// a BoltDB bucket. It is safe for concurrent use.
//
// Ordering: items always flow from oldest (head) to newest (tail). The
// in-memory slice holds the newest MaxMem items; the BoltDB bucket holds
// the older items that overflowed. Drain reads from the head (disk first,
// then memory), so the combined store is a strict FIFO regardless of which
// tier an item lives in.
type SpilloverQueue struct {
	mu       sync.Mutex
	cfg      Config
	db       *bolt.DB
	bucket   []byte
	inMem    [][]byte
	diskSize int64
	dropped  uint64
	seq      uint64
}

// Open creates a new SpilloverQueue and replays any items previously
// persisted to disk. Replay puts the most recent MaxMem items in memory
// and leaves the rest on disk, so the queue resumes exactly where it
// was at shutdown.
func Open(cfg Config) (*SpilloverQueue, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("queue: Path is required")
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("queue: Bucket is required")
	}
	if cfg.MaxMem <= 0 {
		return nil, fmt.Errorf("queue: MaxMem must be > 0")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return nil, fmt.Errorf("queue: mkdir %s: %w", filepath.Dir(cfg.Path), err)
	}

	db, err := bolt.Open(cfg.Path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("queue: open bbolt %s: %w", cfg.Path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(cfg.Bucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("queue: create bucket %s: %w", cfg.Bucket, err)
	}

	q := &SpilloverQueue{
		cfg:    cfg,
		db:     db,
		bucket: []byte(cfg.Bucket),
	}

	if err := q.replay(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("queue: replay: %w", err)
	}

	return q, nil
}

// replay reads items from disk and restores the in-memory slice. Items
// beyond MaxMem remain on disk only. The sequence counter is reset to
// the max sequence seen so subsequent appends don't collide with
// replayed keys. Items promoted to memory are deleted from the bucket
// to preserve the mutually-exclusive invariant (in-memory XOR on-disk).
func (q *SpilloverQueue) replay() error {
	type kv struct {
		key, val []byte
	}
	var entries []kv
	var maxSeq uint64
	err := q.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(q.bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) == 8 {
				s := binary.BigEndian.Uint64(k)
				if s > maxSeq {
					maxSeq = s
				}
			}
			val := make([]byte, len(v))
			copy(val, v)
			entries = append(entries, kv{key: append([]byte(nil), k...), val: val})
			q.diskSize += int64(len(k)) + int64(len(v))
		}
		return nil
	})
	if err != nil {
		return err
	}

	q.seq = maxSeq

	// Split entries into the in-memory tier (newest MaxMem) and the
	// disk tier (older). Cursor order is by ascending sequence, so the
	// newest entries sit at the end of the slice. Items bound for
	// memory are deleted from disk below so the two tiers stay
	// mutually exclusive.
	memN := len(entries)
	if memN > q.cfg.MaxMem {
		memN = q.cfg.MaxMem
	}
	diskN := len(entries) - memN

	q.inMem = make([][]byte, memN)
	memKeys := make([][]byte, memN)
	for i := 0; i < memN; i++ {
		e := entries[diskN+i]
		q.inMem[i] = e.val
		memKeys[i] = e.key
	}

	// Tracked size is the live bytes on disk only — items moved to RAM
	// no longer count against the byte cap.
	q.diskSize = 0
	for i := 0; i < diskN; i++ {
		q.diskSize += int64(len(entries[i].key)) + int64(len(entries[i].val))
	}

	if len(memKeys) > 0 {
		err := q.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(q.bucket)
			for _, k := range memKeys {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// Push appends an item to the queue. If the in-memory slice would
// exceed MaxMem, the oldest item is moved to disk. If the on-disk store
// is at the byte cap, the oldest item on disk is evicted first (and
// counted as Dropped).
func (q *SpilloverQueue) Push(item []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.inMem = append(q.inMem, item)
	if len(q.inMem) <= q.cfg.MaxMem {
		return nil
	}

	// Overflow: move oldest from in-memory to disk.
	evicted := q.inMem[0]
	q.inMem = q.inMem[1:]
	return q.appendToDisk(evicted)
}

// appendToDisk writes an item to BoltDB. If the disk is at the byte
// cap, oldest entries are evicted first. If the item itself is larger
// than the cap (cannot fit even after evicting everything), it is
// dropped and counted.
func (q *SpilloverQueue) appendToDisk(item []byte) error {
	addSize := int64(8 + len(item))

	return q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(q.bucket)

		if q.cfg.MaxBytes > 0 {
			// Item cannot fit at all — drop it before touching the bucket.
			if addSize > q.cfg.MaxBytes {
				q.dropped++
				return nil
			}
			for q.diskSize+addSize > q.cfg.MaxBytes {
				c := b.Cursor()
				k, v := c.First()
				if k == nil {
					break
				}
				if err := b.Delete(k); err != nil {
					return err
				}
				q.diskSize -= int64(len(k)) + int64(len(v))
				q.dropped++
			}
		}

		q.seq++
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, q.seq)
		if err := b.Put(key, item); err != nil {
			return err
		}
		q.diskSize += addSize
		return nil
	})
}

// Drain returns up to n items, oldest first, and removes them from the
// queue. Disk items (the older tier) are drained first; if more items
// are requested than the disk holds, the remainder come from the
// in-memory slice.
func (q *SpilloverQueue) Drain(n int) ([][]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if n <= 0 {
		return nil, nil
	}

	out := make([][]byte, 0, n)

	need := n
	if err := q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(q.bucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil && need > 0; k, v = c.Next() {
			buf := make([]byte, len(v))
			copy(buf, v)
			out = append(out, buf)
			if err := b.Delete(k); err != nil {
				return err
			}
			q.diskSize -= int64(len(k)) + int64(len(v))
			need--
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if need > 0 && len(q.inMem) > 0 {
		take := need
		if take > len(q.inMem) {
			take = len(q.inMem)
		}
		out = append(out, q.inMem[:take]...)
		q.inMem = q.inMem[take:]
	}

	return out, nil
}

// Depth returns the number of items currently in the in-memory slice.
func (q *SpilloverQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.inMem)
}

// InMem returns a copy of the in-memory items in their current order
// (oldest first). Intended for tests and metrics; production code
// should use Drain to consume items.
func (q *SpilloverQueue) InMem() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([][]byte, len(q.inMem))
	for i, b := range q.inMem {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

// DiskCount returns the number of items currently persisted to BoltDB.
func (q *SpilloverQueue) DiskCount() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var n int
	err := q.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(q.bucket)
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

// DiskSize returns the BoltDB file size in bytes (the on-disk footprint,
// including free pages bbolt keeps around for reuse).
func (q *SpilloverQueue) DiskSize() (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	fi, err := os.Stat(q.cfg.Path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// TrackedSize returns the sum of stored key+value bytes (i.e., the live
// data size excluding bbolt's free pages). This is the number that
// MaxBytes caps.
func (q *SpilloverQueue) TrackedSize() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.diskSize
}

// Dropped returns the cumulative count of items evicted from disk due
// to the byte cap.
func (q *SpilloverQueue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// Close flushes any in-memory items to disk, then closes the underlying
// BoltDB. Flushing is required for the mutually-exclusive design: in
// RAM we only hold the newest MaxMem items, and the rest live in
// BoltDB. Without flushing, a graceful shutdown would lose the hot
// items until the next replay (which still works — the cold items
// survive — but Flush makes the next process's view of the queue
// complete).
func (q *SpilloverQueue) Close() error {
	// Hold q.mu for the whole close. appendToDisk mutates diskSize/dropped and
	// writes BoltDB and is a lock-required helper (Push/Drain only ever call it
	// while holding q.mu); flushing it after releasing the lock raced any
	// concurrent Push/Drain on those fields and on the BoltDB transaction.
	// Keeping the lock also guarantees no Push/Drain is mid-transaction when the
	// database is closed.
	q.mu.Lock()
	defer q.mu.Unlock()

	mem := q.inMem
	q.inMem = nil

	for _, item := range mem {
		if err := q.appendToDisk(item); err != nil {
			_ = q.db.Close()
			return err
		}
	}

	return q.db.Close()
}
