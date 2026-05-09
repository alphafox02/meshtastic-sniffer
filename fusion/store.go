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
// Storage layout (single bbolt file):
//
//	bucket "events"
//	  key:   8-byte big-endian monotonic sequence number
//	  value: raw event JSON bytes (same as the SSE wire format)
//
// Ring trimming: every Append checks the bucket size and deletes the
// oldest entries until count <= maxEntries. maxEntries defaults to
// the SSE ring size; operators wanting a longer history can set
// fusionMaxEntries higher (or run a follow-on archive sink).

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const eventsBucket = "events"

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
		_, err := tx.CreateBucketIfNotExists([]byte(eventsBucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &EventStore{db: db, maxEntries: maxEntries}, nil
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
