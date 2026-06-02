// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/store.go: durable SSE replay ring backed by bbolt.
//
// The SSEHub holds a 1024-event ring in memory so a browser refresh
// rehydrates the dashboard from recent traffic without waiting for new
// frames. That ring is lost when the fusion process exits. EventStore
// mirrors the ring to disk so the next process startup preloads it.
//
// Storage layout (single bbolt file, schema_version=2):
//
//	bucket "meta"
//	  key:   "schema_version"  value: ASCII integer
//	  key:   "created_by"      value: identifier string
//
//	bucket "events"
//	  key:   8-byte big-endian monotonic sequence number
//	  value: raw event JSON bytes (same as the SSE wire format)
//
//	bucket "cluster_observations"   (schema v2; empty until write paths land)
//	  key:   per-event composite (event_id | from | packet_id | cluster_time_ns)
//	  value: JSON encoding the participating stations' raw Observations
//	         (lat/lon/alt, PreambleLockTNs, StationTNs, TAccNs, SNR/RSSI,
//	          freq/preset/SF/CR/BW) for replay re-solve.
//
//	bucket "pair_snapshots"         (schema v2; empty until write paths land)
//	  key:   snapshot_time_ns (8 BE bytes) | pair_key (variable; "A|B")
//	  value: JSON {median_ns, mad_ns, sample_count, anchor_ids,
//	              status_at_snapshot, last_anchor_time_ns, max_age_s}
//	  notes: snapshot_time_ns is the RF event time (max preamble_lock_t_ns
//	         of the anchor cluster that triggered the update), not wall clock.
//
// Ring trimming: every Append checks the events bucket size and deletes
// the oldest entries until count <= maxEntries. maxEntries defaults to
// the SSE ring size; operators wanting a longer history can set
// fusionMaxEntries higher (or run a follow-on archive sink).
//
// Schema compatibility:
//   - An older binary opening a newer file ignores unknown buckets.
//   - A newer binary opening an older file (missing v2 buckets / version)
//     keeps live dashboard behavior and disables replay/re-solve. No
//     migration is run; the missing buckets are created idempotently on
//     the next OpenEventStore so the file becomes v2-shaped after one
//     more run.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	// Bucket names.
	eventsBucket              = "events"
	metaBucket                = "meta"
	clusterObservationsBucket = "cluster_observations"
	pairSnapshotsBucket       = "pair_snapshots"

	// Current schema version. Bumped when a future change requires a
	// migration step beyond CreateBucketIfNotExists.
	schemaVersion = 2

	// Meta-bucket keys.
	metaKeySchemaVersion = "schema_version"
	metaKeyCreatedBy     = "created_by"
	metaCreatedByValue   = "meshtastic-fusion"
)

// EventStore persists the SSE replay ring across fusion restarts.
//
// Append is fire-and-forget: errors are logged but do not block the
// publisher. Recent reads the last n entries oldest-to-newest for
// hydrating the SSEHub on startup.
type EventStore struct {
	db         *bolt.DB
	maxEntries int
}

// OpenEventStore opens or creates a bbolt file at `path`. Returns
// (nil, nil) when path is empty (memory-only mode). maxEntries caps
// the on-disk ring; entries past the cap are deleted on each Append.
func OpenEventStore(path string, maxEntries int) (*EventStore, error) {
	if path == "" {
		return nil, nil
	}
	if maxEntries <= 0 {
		maxEntries = sseHistorySize
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = ensureDir(dir)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("bolt open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		// Create / verify every bucket in the v2 layout. Older
		// databases gain the new buckets on first open under a v2
		// binary; their existing 'events' bucket and contents are
		// preserved untouched.
		for _, name := range []string{
			eventsBucket,
			metaBucket,
			clusterObservationsBucket,
			pairSnapshotsBucket,
		} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create %s bucket: %w", name, err)
			}
		}
		// Record the schema version. If a key is already present from a
		// prior run we only overwrite when the prior value was lower --
		// never downgrade a number that a future binary might have
		// written.
		mb := tx.Bucket([]byte(metaBucket))
		if existing := mb.Get([]byte(metaKeySchemaVersion)); existing == nil {
			if err := mb.Put([]byte(metaKeySchemaVersion),
				[]byte(strconv.Itoa(schemaVersion))); err != nil {
				return err
			}
		} else {
			if prev, err := strconv.Atoi(string(existing)); err == nil && prev < schemaVersion {
				if err := mb.Put([]byte(metaKeySchemaVersion),
					[]byte(strconv.Itoa(schemaVersion))); err != nil {
					return err
				}
			}
		}
		if mb.Get([]byte(metaKeyCreatedBy)) == nil {
			if err := mb.Put([]byte(metaKeyCreatedBy),
				[]byte(metaCreatedByValue)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &EventStore{db: db, maxEntries: maxEntries}, nil
}

// SchemaVersion returns the schema version recorded in the meta
// bucket, or 0 when the meta bucket is missing / unreadable / the key
// is absent. The 0 case lets callers detect a pre-v2 file even after
// OpenEventStore has created the buckets idempotently: schemaVersion
// will be 2 once written, so a 0 indicates either an empty file or a
// future write that hasn't happened yet.
func (s *EventStore) SchemaVersion() int {
	if s == nil || s.db == nil {
		return 0
	}
	var v int
	_ = s.db.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		if mb == nil {
			return nil
		}
		raw := mb.Get([]byte(metaKeySchemaVersion))
		if raw == nil {
			return nil
		}
		parsed, err := strconv.Atoi(string(raw))
		if err == nil {
			v = parsed
		}
		return nil
	})
	return v
}

// ReplayAvailable reports whether the on-disk schema is at the version
// that supports replay / re-solve. Currently equivalent to "schema
// version >= 2," but the function exists so callers do not hardcode
// the version number. Write paths for cluster_observations and
// pair_snapshots land in the next two commits; until then this
// returns true for any v2 file regardless of whether the new buckets
// have content.
func (s *EventStore) ReplayAvailable() bool {
	return s.SchemaVersion() >= 2
}

// Close releases the underlying bbolt file. Safe to call on nil.
func (s *EventStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Append writes one event to the on-disk ring and trims older entries
// past maxEntries. Returns an error only on storage failure; callers
// generally log and continue so the live publisher path is unaffected.
func (s *EventStore) Append(payload []byte) error {
	if s == nil || s.db == nil {
		return nil
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(eventsBucket))
		if b == nil {
			return errors.New("events bucket missing")
		}
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		if err := b.Put(key[:], cp); err != nil {
			return err
		}
		// Trim. Cheap because keys are sequence-ordered: walk forward
		// from the start and delete until count fits. Counting via
		// ForEach rather than Stats() so we observe the just-Put'd
		// key reliably (Stats may lag inside a write tx).
		n := 0
		_ = b.ForEach(func(_, _ []byte) error { n++; return nil })
		excess := n - s.maxEntries
		if excess > 0 {
			c := b.Cursor()
			for k, _ := c.First(); k != nil && excess > 0; k, _ = c.Next() {
				if err := c.Delete(); err != nil {
					return err
				}
				excess--
			}
		}
		return nil
	})
}

// Recent returns up to `n` most-recent events oldest-to-newest. Used
// to prefill the SSEHub's in-memory ring at startup so browsers
// reconnecting see the same recent history they would have seen if
// fusion had never restarted.
func (s *EventStore) Recent(n int) ([][]byte, error) {
	if s == nil || s.db == nil || n <= 0 {
		return nil, nil
	}
	out := make([][]byte, 0, n)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(eventsBucket))
		if b == nil {
			return nil
		}
		// Walk newest-to-oldest, collect up to n, then reverse.
		c := b.Cursor()
		for k, v := c.Last(); k != nil && len(out) < n; k, v = c.Prev() {
			cp := make([]byte, len(v))
			copy(cp, v)
			out = append(out, cp)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// Count returns the current number of stored events. Useful for tests
// and the dashboard's "events archived" stat.
func (s *EventStore) Count() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(eventsBucket))
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}
