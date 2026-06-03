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
// Storage layout (single bbolt file, schema_version=3):
//
//	bucket "meta"
//	  key:   "schema_version"  value: ASCII integer
//	  key:   "created_by"      value: identifier string
//
//	bucket "events"
//	  key:   8-byte big-endian monotonic sequence number
//	  value: raw event JSON bytes (same as the SSE wire format)
//
//	bucket "cluster_observations"   (schema v2)
//	  key:   per-event composite (event_id | from | packet_id | cluster_time_ns)
//	  value: JSON encoding the participating stations' raw Observations
//	         (lat/lon/alt, PreambleLockTNs, StationTNs, TAccNs, SNR/RSSI,
//	          freq/preset/SF/CR/BW) for replay re-solve.
//
//	bucket "pair_snapshots"         (schema v2)
//	  key:   snapshot_time_ns (8 BE bytes) | pair_key (variable; "A|B")
//	  value: JSON {median_ns, mad_ns, sample_count, anchor_ids,
//	              status_at_snapshot, last_anchor_time_ns, max_age_s}
//	  notes: snapshot_time_ns is the RF event time (max preamble_lock_t_ns
//	         of the anchor cluster that triggered the update), not wall clock.
//
//	bucket "solved_fixes"           (schema v3)
//	  key:   event_time_ns (8 BE bytes) | "<from>|<packet_id>|<emission_seq>"
//	  value: JSON encoding the MlatResult + cluster metadata at solve time:
//	         lat, lon, uncertainty_m, station_count, iterations,
//	         timestamp_class, timestamp_class_degraded, clock_sync_*,
//	         and the raw GEOLOCATED wire JSON. Lets the Evidence tab
//	         render historical solves without re-running Solve.
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
	"encoding/json"
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
	solvedFixesBucket         = "solved_fixes"

	// Current schema version. Bumped when a future change requires a
	// migration step beyond CreateBucketIfNotExists.
	schemaVersion = 3

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
			solvedFixesBucket,
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
// that supports replay / re-solve. Equivalent to "schema version >= 2"
// (the version that introduced cluster_observations + pair_snapshots);
// solved_fixes (v3) is additive on top and not required for the basic
// "replay these cluster observations" path. The function exists so
// callers do not hardcode the version number.
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

// ---- cluster_observations: persisted RF evidence for replay ----
//
// Each row is one flushed Cluster's worth of station-side observations,
// frozen so a future replay/re-solve has the same per-station inputs the
// live solver consumed. The key is sortable by RF event time so the
// dashboard can scan a time window in one cursor walk.

// ClusterObservationRecord is the on-disk shape of one cluster_observations
// row. Cluster-level fields up front, per-station array below.
//
// EmissionSeq distinguishes multiple RF emissions of the same (from,
// packet_id): the first emission is seq=0 (back-compat key shape),
// retransmits/relays caught in the same dedup window get seq=1, 2, ...
// LowTrust marks clusters that relied on the wall-clock fallback because
// one or more participating observations lacked preamble_lock_t_ns.
// StationDupesSuppressed counts per-station collisions resolved by
// keeping the better observation (higher class, then higher SNR).
type ClusterObservationRecord struct {
	From                   string                      `json:"from"`
	PacketID               uint32                      `json:"packet_id"`
	EmissionSeq            int                         `json:"emission_seq,omitempty"`
	ClusterTimeNs          uint64                      `json:"cluster_time_ns"`
	FirstSeenWallNs        uint64                      `json:"first_seen_wall_ns"`
	Preset                 string                      `json:"preset,omitempty"`
	SF                     int                         `json:"sf,omitempty"`
	CR                     int                         `json:"cr,omitempty"`
	BwHz                   int                         `json:"bw_hz,omitempty"`
	FreqHz                 uint64                      `json:"freq_hz,omitempty"`
	ChannelName            string                      `json:"channel_name,omitempty"`
	LowTrust               bool                        `json:"low_trust,omitempty"`
	StationDupesSuppressed int                         `json:"station_dupes_suppressed,omitempty"`
	Observations           []ClusterObservationStation `json:"observations"`
}

// ClusterObservationStation is one (station, frame) tuple inside a record.
// Mirrors the fields the solver consumes plus the SNR/RSSI signal
// quality that a dashboard wants for the per-event detail panel.
type ClusterObservationStation struct {
	Station         string  `json:"station"`
	StationLat      float64 `json:"station_lat"`
	StationLon      float64 `json:"station_lon"`
	StationAltM     float64 `json:"station_alt_m,omitempty"`
	StationTNs      uint64  `json:"station_t_ns"`
	StationTAccNs   uint32  `json:"station_t_acc_ns"`
	PreambleLockTNs uint64  `json:"preamble_lock_t_ns,omitempty"`
	SnrDB           float64 `json:"snr_db,omitempty"`
	RssiDB          float64 `json:"rssi_db,omitempty"`
}

// clusterObsKey encodes a row key sortable by cluster_time_ns ascending.
// Format: 8 BE bytes of nanoseconds, then ASCII "|<from>|<packet_id>" so
// (1) ties at the same nanosecond are disambiguated and (2) replay can
// do bytes.HasPrefix(key, time_prefix) to walk a single instant.
func clusterObsKey(clusterTimeNs uint64, from string, packetID uint32) []byte {
	out := make([]byte, 0, 8+1+len(from)+1+10)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], clusterTimeNs)
	out = append(out, ts[:]...)
	out = append(out, '|')
	out = append(out, []byte(from)...)
	out = append(out, '|')
	out = strconv.AppendUint(out, uint64(packetID), 10)
	return out
}

// WriteClusterObservation persists one ClusterObservationRecord. Safe to
// call on a nil EventStore (no-op, returns nil) so live mode without a
// state DB stays compatible. Errors are returned but generally the
// caller logs-and-continues so the live publish path is unaffected.
func (s *EventStore) WriteClusterObservation(rec *ClusterObservationRecord) error {
	if s == nil || s.db == nil || rec == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal cluster observation: %w", err)
	}
	key := clusterObsKey(rec.ClusterTimeNs, rec.From, rec.PacketID)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(clusterObservationsBucket))
		if b == nil {
			return errors.New("cluster_observations bucket missing")
		}
		return b.Put(key, payload)
	})
}

// ReadClusterObservationsRange returns every record whose ClusterTimeNs
// falls in [startNs, endNs]. Walk is one cursor pass; the key encoding
// puts the timestamp first so seeking is O(log N) + iteration.
//
// Used by the future replay/re-solve path: "show me everything fusion
// heard between 14:03:00 and 14:04:00 UTC yesterday."
func (s *EventStore) ReadClusterObservationsRange(startNs, endNs uint64) ([]ClusterObservationRecord, error) {
	if s == nil || s.db == nil || endNs < startNs {
		return nil, nil
	}
	var out []ClusterObservationRecord
	var startKey [8]byte
	binary.BigEndian.PutUint64(startKey[:], startNs)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(clusterObservationsBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(startKey[:]); k != nil; k, v = c.Next() {
			if len(k) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(k[:8])
			if ts > endNs {
				break
			}
			var rec ClusterObservationRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal cluster observation at ts=%d: %w", ts, err)
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

// CountClusterObservations returns the current row count. Useful for the
// dashboard's "evidence retained" stat and for tests.
func (s *EventStore) CountClusterObservations() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(clusterObservationsBucket))
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

// ---- pair_snapshots: persisted clock-pair offsets for replay ----
//
// Every anchor FeedCluster() that updates pair state emits one row per
// touched pair. The key sorts by RF event time so replay can find the
// pair-offset model that was valid at any given moment ("what was the
// (alpha, bravo) offset when packet 7e5dd49a arrived?") with one
// cursor seek.

// PairSnapshotRecord is the on-disk shape of one pair-offset row. Each
// field comes straight from PairOffset / pairStatusNow at the moment
// the anchor cluster was processed.
type PairSnapshotRecord struct {
	PairKey            string   `json:"pair_key"`             // "A|B" lex-sorted
	SnapshotTimeNs     uint64   `json:"snapshot_time_ns"`     // RF event time of the triggering anchor cluster
	LastAnchorTimeNs   uint64   `json:"last_anchor_time_ns"`  // max RF time across samples currently in the ring
	MedianNs           float64  `json:"median_ns"`            // robust per-pair offset estimate
	MadNs              float64  `json:"mad_ns"`               // residual; converged when <= MaxMADNs
	SampleCount        int      `json:"sample_count"`         // size of the in-memory ring at snapshot time
	AnchorIDs          []string `json:"anchor_ids"`           // distinct from-ids that contributed
	StatusAtSnapshot   string   `json:"status_at_snapshot"`   // warming | converged | stale | rejected | none
	MaxAgeS            float64  `json:"max_age_s"`            // policy at snapshot time; replay reuses it
}

// pairSnapshotKey: 8 BE bytes of snapshot_time_ns then "|<pair_key>".
// Same shape as clusterObsKey -- time-first for sortable scans.
func pairSnapshotKey(snapshotTimeNs uint64, pairKey string) []byte {
	out := make([]byte, 0, 8+1+len(pairKey))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], snapshotTimeNs)
	out = append(out, ts[:]...)
	out = append(out, '|')
	out = append(out, []byte(pairKey)...)
	return out
}

// WritePairSnapshot persists one PairSnapshotRecord. No-op on nil
// EventStore or nil record so the live publish path stays unaffected
// when running without --state-db.
func (s *EventStore) WritePairSnapshot(rec *PairSnapshotRecord) error {
	if s == nil || s.db == nil || rec == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal pair snapshot: %w", err)
	}
	key := pairSnapshotKey(rec.SnapshotTimeNs, rec.PairKey)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(pairSnapshotsBucket))
		if b == nil {
			return errors.New("pair_snapshots bucket missing")
		}
		return b.Put(key, payload)
	})
}

// ReadPairSnapshotsRange returns every snapshot whose SnapshotTimeNs
// falls in [startNs, endNs]. Used by the future timeline UI to render
// a "clock health over time" graph for one or more pairs.
func (s *EventStore) ReadPairSnapshotsRange(startNs, endNs uint64) ([]PairSnapshotRecord, error) {
	if s == nil || s.db == nil || endNs < startNs {
		return nil, nil
	}
	var out []PairSnapshotRecord
	var startKey [8]byte
	binary.BigEndian.PutUint64(startKey[:], startNs)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(pairSnapshotsBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(startKey[:]); k != nil; k, v = c.Next() {
			if len(k) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(k[:8])
			if ts > endNs {
				break
			}
			var rec PairSnapshotRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal pair snapshot at ts=%d: %w", ts, err)
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

// LatestPairSnapshotAtOrBefore returns the newest snapshot for the
// given pair whose SnapshotTimeNs is <= eventTimeNs. This is the
// canonical replay lookup: "what was this pair's offset when the
// target packet arrived?" Returns (nil, false) when no snapshot
// exists (pair was never seen by this fusion process, or the file
// was rotated past the row).
//
// The walk goes newest-to-oldest -- the very first matching pair_key
// is the answer, so most queries finish in O(snapshots-per-pair-since-T).
func (s *EventStore) LatestPairSnapshotAtOrBefore(eventTimeNs uint64, pairKey string) (*PairSnapshotRecord, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, nil
	}
	var out *PairSnapshotRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(pairSnapshotsBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		// Seek to one past the event timestamp; Prev() then lands on
		// the latest key <= eventTime.
		var seek [9]byte
		binary.BigEndian.PutUint64(seek[:8], eventTimeNs)
		seek[8] = 0xFF // place sentinel between same-ts rows
		c.Seek(seek[:])
		for k, v := c.Prev(); k != nil; k, v = c.Prev() {
			if len(k) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(k[:8])
			if ts > eventTimeNs {
				continue
			}
			// Key suffix after the leading 8 BE bytes + '|' is the pair_key.
			if len(k) < 9 || k[8] != '|' {
				continue
			}
			if string(k[9:]) != pairKey {
				continue
			}
			var rec PairSnapshotRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal pair snapshot at ts=%d: %w", ts, err)
			}
			out = &rec
			found = true
			return nil
		}
		return nil
	})
	return out, found, err
}

// CountPairSnapshots returns the on-disk row count for the bucket.
func (s *EventStore) CountPairSnapshots() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(pairSnapshotsBucket))
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

// ---- solved_fixes: cached MlatResult per RF event for the Evidence tab ----
//
// The dashboard's per-event detail panel should show "what was the solved
// location, how trusted, which clock model" without re-running Solve just
// to display history. solved_fixes mirrors what the live event loop
// produced once into a sortable, time-keyed bucket so the timeline can
// fetch a window's worth of fixes in one cursor walk.
//
// Modest v1 scope: no per-station residuals, no solver-internals redesign,
// no DOP/geometry math. Cache the fields we already compute.

// SolvedFixRecord is the on-disk shape of one solved_fixes row.
// EmissionSeq disambiguates two distinct RF emissions of the same
// (from, packet_id); SolutionTimeNs records when the live solver actually
// ran (wall clock), distinct from EventTimeNs (RF event time, primary
// sort key).
type SolvedFixRecord struct {
	EventTimeNs    uint64 `json:"event_time_ns"`
	SolutionTimeNs uint64 `json:"solution_time_ns"`
	From           string `json:"from"`
	PacketID       uint32 `json:"packet_id"`
	EmissionSeq    int    `json:"emission_seq,omitempty"`
	ClusterKey     string `json:"cluster_key"`

	Lat            float64 `json:"lat"`
	Lon            float64 `json:"lon"`
	UncertaintyM   float64 `json:"uncertainty_m"`
	StationCount   int     `json:"station_count"`
	Iterations     int     `json:"iterations"`
	TimestampClass string  `json:"timestamp_class"`
	Degraded       bool    `json:"timestamp_class_degraded,omitempty"`

	ClockSyncPairCount   int     `json:"clock_sync_pair_count"`
	ClockSyncResidualNs  float64 `json:"clock_sync_residual_ns"`
	ClockSyncAnchorCount int     `json:"clock_sync_anchor_count"`
	ClockSyncReference   string  `json:"clock_sync_reference,omitempty"`

	// Optional metadata: the pair keys considered when solving this fix
	// and the snapshot keys those offsets came from. Populated when
	// readily available from clock-sync state; absent on solves that ran
	// without clock-sync.
	PairKeysConsidered   []string `json:"pair_keys_considered,omitempty"`
	PairSnapshotKeysUsed []string `json:"pair_snapshot_keys_used,omitempty"`

	// Raw GEOLOCATED wire JSON. Lets a replay UI display the exact event
	// shape the live SSE feed published, without re-marshalling. Stored
	// as a JSON-encoded string (base64 in the on-disk JSON) so the wire
	// payload round-trips exactly.
	RawGeolocatedJSON []byte `json:"raw_geolocated_json,omitempty"`
}

// solvedFixKey encodes a row key sortable by event_time_ns ascending.
// Format mirrors clusterObsKey / pairSnapshotKey: 8 BE bytes of nanoseconds
// then ASCII "|<from>|<packet_id>|<emission_seq>" so a time-range cursor
// walk lands the right rows and per-emission disambiguation survives a
// nanosecond collision between distinct same-(from,pid) emissions.
func solvedFixKey(eventTimeNs uint64, from string, packetID uint32, emissionSeq int) []byte {
	out := make([]byte, 0, 8+1+len(from)+1+10+1+10)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], eventTimeNs)
	out = append(out, ts[:]...)
	out = append(out, '|')
	out = append(out, []byte(from)...)
	out = append(out, '|')
	out = strconv.AppendUint(out, uint64(packetID), 10)
	out = append(out, '|')
	out = strconv.AppendInt(out, int64(emissionSeq), 10)
	return out
}

// WriteSolvedFix persists one SolvedFixRecord. Safe to call on a nil
// EventStore (no-op, returns nil). Errors are returned but callers
// typically log-and-continue so the live SSE publish path is unaffected.
func (s *EventStore) WriteSolvedFix(rec *SolvedFixRecord) error {
	if s == nil || s.db == nil || rec == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal solved fix: %w", err)
	}
	key := solvedFixKey(rec.EventTimeNs, rec.From, rec.PacketID, rec.EmissionSeq)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(solvedFixesBucket))
		if b == nil {
			return errors.New("solved_fixes bucket missing")
		}
		return b.Put(key, payload)
	})
}

// ReadSolvedFixesRange returns every record whose EventTimeNs falls in
// [startNs, endNs]. One cursor pass; the key encoding puts the timestamp
// first so seeking is O(log N) + iteration.
func (s *EventStore) ReadSolvedFixesRange(startNs, endNs uint64) ([]SolvedFixRecord, error) {
	if s == nil || s.db == nil || endNs < startNs {
		return nil, nil
	}
	var out []SolvedFixRecord
	var startKey [8]byte
	binary.BigEndian.PutUint64(startKey[:], startNs)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(solvedFixesBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(startKey[:]); k != nil; k, v = c.Next() {
			if len(k) < 8 {
				continue
			}
			ts := binary.BigEndian.Uint64(k[:8])
			if ts > endNs {
				break
			}
			var rec SolvedFixRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal solved fix at ts=%d: %w", ts, err)
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

// CountSolvedFixes returns the on-disk row count for the bucket.
func (s *EventStore) CountSolvedFixes() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(solvedFixesBucket))
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}
