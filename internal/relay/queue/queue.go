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
	"sync/atomic"
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
	// SyncInterval bounds how often the spillover file is fsync'd. The BoltDB is
	// opened with NoSync so the hot Push path never blocks on a per-write fsync
	// (the 2026-06-23 audit M7 stall, which dropped sFlow under load); durability
	// instead comes from an fsync at most once per SyncInterval plus an
	// unconditional fsync on Close. A process restart loses nothing — committed
	// pages live in the OS page cache and survive process exit, and bbolt's
	// dual-meta pages recover cleanly — so the AUDIT-058 restart/outage guarantee
	// holds; only a kernel crash / power loss can lose up to SyncInterval of the
	// most-recent items, an acceptable trade for a sampled-telemetry buffer.
	// 0 → 2s default.
	SyncInterval time.Duration
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
	mu           sync.Mutex
	cfg          Config
	db           *bolt.DB
	bucket       []byte
	inMem        [][]byte
	diskSize     int64
	dropped      uint64
	seq          uint64
	syncInterval time.Duration
	dirty        atomic.Bool // set on write, cleared by the background sync (M18)

	syncStop chan struct{}
	syncDone chan struct{}
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

	syncInterval := cfg.SyncInterval
	if syncInterval <= 0 {
		syncInterval = 2 * time.Second
	}

	q, err := openAndReplay(cfg, syncInterval)
	if err != nil {
		// M17 of the 2026-07-01 audit: the DB is opened NoSync, under which a
		// power loss can CORRUPT the file (not just truncate it) — bbolt's own
		// docs warn of this, and the dual-meta recovery only helps when each
		// commit was fsync-barriered. Pre-fix, a corrupt file failed Open, and
		// the caller (ensureQueues) then disabled ALL SEVEN queues on any
		// single failure — one power event silently removed all outage
		// buffering until an operator manually deleted the .bolt file. Instead:
		// quarantine the unreadable file and recreate a fresh DB, so durability
		// self-heals go-forward (losing only the already-unreadable spool).
		quarantine := fmt.Sprintf("%s.corrupt-%d", cfg.Path, time.Now().UnixNano())
		if rerrr := os.Rename(cfg.Path, quarantine); rerrr != nil {
			return nil, fmt.Errorf("queue: %s unreadable (%v) and could not quarantine it: %w", cfg.Path, err, rerrr)
		}
		fmt.Printf("[queue] WARNING: %s was unreadable (%v); quarantined to %s and recreating a fresh spool (buffered data in the corrupt file is lost)\n", cfg.Path, err, quarantine)
		q, err = openAndReplay(cfg, syncInterval)
		if err != nil {
			return nil, fmt.Errorf("queue: recreate after quarantine: %w", err)
		}
	}

	// M18: fsync happens on a background ticker, NOT under q.mu on the hot
	// Push path. Pre-fix, appendToDisk called db.Sync() (a full-file fsync of
	// a potentially ~1 GiB spool) while holding the mutex shared by every UDP
	// ingest worker, so the periodic stall blocked all workers and could drop
	// datagrams precisely under the flood/outage the queue exists to cover.
	q.syncStop = make(chan struct{})
	q.syncDone = make(chan struct{})
	go q.syncLoop()

	return q, nil
}

// openAndReplay opens the bbolt file, ensures the bucket exists, and replays
// the on-disk tier into memory. Returns an error (leaving nothing open) if the
// file is unreadable/corrupt — the signal M17's quarantine path acts on.
func openAndReplay(cfg Config, syncInterval time.Duration) (*SpilloverQueue, error) {
	// NoSync: the hot Push path must not block on a per-write fsync (audit M7).
	// Durability is the background fsync (≤ once per syncInterval, M18) plus an
	// unconditional fsync in Close. See Config.SyncInterval.
	db, err := bolt.Open(cfg.Path, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoSync: true})
	if err != nil {
		return nil, fmt.Errorf("open bbolt %s: %w", cfg.Path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(cfg.Bucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create bucket %s: %w", cfg.Bucket, err)
	}
	q := &SpilloverQueue{
		cfg:          cfg,
		db:           db,
		bucket:       []byte(cfg.Bucket),
		syncInterval: syncInterval,
	}
	if err := q.replay(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("replay: %w", err)
	}
	return q, nil
}

// syncLoop fsyncs the spillover file at most once per syncInterval, off the
// hot path (M18). It only syncs when a write happened since the last sync, so
// an idle queue never fsyncs. Stopped by Close.
func (q *SpilloverQueue) syncLoop() {
	defer close(q.syncDone)
	ticker := time.NewTicker(q.syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-q.syncStop:
			return
		case <-ticker.C:
			if q.dirty.CompareAndSwap(true, false) {
				if err := q.db.Sync(); err != nil {
					q.dirty.Store(true) // retry next tick
				}
			}
		}
	}
}

// replay reads items from disk and restores the in-memory slice. Items
// beyond MaxMem remain on disk only. The sequence counter is reset to
// the max sequence seen so subsequent appends don't collide with
// replayed keys. Items promoted to memory are deleted from the bucket
// to preserve the mutually-exclusive invariant (in-memory XOR on-disk).
// H7 of the 2026-07-01 audit: the pre-fix replay copied EVERY key+value
// in the bucket into a heap slice before deciding which MaxMem items
// stay in memory — after the multi-day outage this queue exists to
// survive, that meant allocating the entire spool (up to MaxBytes,
// default 1 GiB, times 7 queues) at startup, OOM-killing the collector
// on memory-constrained probe hosts and crash-looping it (each restart
// re-replayed, and the crash prevented the drain that would shrink the
// spool). Now the cursor walks BACKWARD (newest → oldest): only the
// newest MaxMem values are copied into RAM; everything older is counted
// by key/value LENGTH only, with no value copies — peak replay heap is
// bounded by MaxMem items regardless of spool size.
func (q *SpilloverQueue) replay() error {
	var memVals [][]byte // newest MaxMem values, collected newest-first
	var memKeys [][]byte // their keys (delete order doesn't matter)
	var maxSeq uint64
	var diskBytes int64
	err := q.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(q.bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if len(k) == 8 {
				s := binary.BigEndian.Uint64(k)
				if s > maxSeq {
					maxSeq = s
				}
			}
			if len(memVals) < q.cfg.MaxMem {
				memVals = append(memVals, append([]byte(nil), v...))
				memKeys = append(memKeys, append([]byte(nil), k...))
			} else {
				// Disk tier: track live bytes only — no value copy.
				diskBytes += int64(len(k)) + int64(len(v))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	q.seq = maxSeq

	// memVals was collected newest-first; the in-memory tier is
	// oldest-first (FIFO tail), so reverse into place.
	n := len(memVals)
	q.inMem = make([][]byte, n)
	for i := 0; i < n; i++ {
		q.inMem[i] = memVals[n-1-i]
	}

	// Tracked size is the live bytes on disk only — items moved to RAM
	// no longer count against the byte cap.
	q.diskSize = diskBytes

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

	if err := q.db.Update(func(tx *bolt.Tx) error {
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
	}); err != nil {
		return err
	}

	// M18: the commit above did not fsync (NoSync). Just mark the queue dirty;
	// the background syncLoop fsyncs off the hot path so this write — and the
	// q.mu it holds, shared by every UDP ingest worker — never blocks on a
	// full-file fsync. Data is process-restart durable via the OS page cache
	// meanwhile; the fsync only guards against kernel crash / power loss.
	q.dirty.Store(true)
	return nil
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
	// M18: stop the background sync loop first so it can't race the final
	// fsync/close below.
	if q.syncStop != nil {
		close(q.syncStop)
		<-q.syncDone
		q.syncStop = nil
	}

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

	// Graceful shutdown is fully durable: force a final fsync (the DB is opened
	// NoSync, so db.Close alone would not flush the throttled-but-unsynced tail).
	if err := q.db.Sync(); err != nil {
		_ = q.db.Close()
		return err
	}
	return q.db.Close()
}
