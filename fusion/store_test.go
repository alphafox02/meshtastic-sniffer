// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

func TestEventStore_AppendAndRecent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 10; i++ {
		if err := s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got, err := s.Recent(5)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5", len(got))
	}
	// Recent returns oldest-to-newest; we appended 0..9 so the last 5 are 5..9.
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i+5))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s", i, ev, want)
		}
	}
}

func TestEventStore_RingTrimsAtCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 5)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 20; i++ {
		if err := s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := s.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 5 {
		t.Fatalf("count=%d want 5 (ring should trim past cap)", n)
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5", len(got))
	}
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i+15))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s (oldest-to-newest ordering)", i, ev, want)
		}
	}
}

func TestEventStore_PersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s1, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	for i := 0; i < 7; i++ {
		_ = s1.Append([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	// Reopen and verify the events are still there.
	s2, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer s2.Close()
	got, err := s2.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("len(got)=%d want 7", len(got))
	}
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s", i, ev, want)
		}
	}
}

func TestEventStore_NilSafe(t *testing.T) {
	var s *EventStore
	if err := s.Append([]byte(`{}`)); err != nil {
		t.Fatalf("nil append: %v", err)
	}
	got, err := s.Recent(10)
	if err != nil || got != nil {
		t.Fatalf("nil recent: got=%v err=%v", got, err)
	}
	n, err := s.Count()
	if err != nil || n != 0 {
		t.Fatalf("nil count: %d err=%v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
}

func TestEventStore_EmptyPathReturnsNil(t *testing.T) {
	s, err := OpenEventStore("", 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store for empty path, got %v", s)
	}
}

func TestSSEHub_PublishMirrorsToStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	hub := newSSEHub()
	hub.AttachStore(s)

	for i := 0; i < 5; i++ {
		hub.Publish([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5 (Publish didn't mirror to store)", len(got))
	}
}

func TestSSEHub_HydratesFromStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 4; i++ {
		_ = s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	hub := newSSEHub()
	if err := hub.HydrateFromStore(s); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	hub.AttachStore(s)
	defer s.Close()

	// New SSE client should see all 4 events on connect via the
	// register replay path.
	_, replay, unregister := hub.register()
	defer unregister()
	if len(replay) != 4 {
		t.Fatalf("replay len=%d want 4 (hub didn't preload from store)", len(replay))
	}
	for i, ev := range replay {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i))
		if !bytes.Equal(ev, want) {
			t.Fatalf("replay[%d] = %s, want %s", i, ev, want)
		}
	}
}

// TestEventStore_SchemaV2 verifies the store records schema_version=2
// and creates the cluster_observations + pair_snapshots buckets.
// Re-opening the same file is a no-op for the version field (no
// downgrade, no duplicate write).
func TestEventStore_SchemaV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := s.SchemaVersion(); got != 2 {
		t.Errorf("SchemaVersion=%d, want 2", got)
	}
	if !s.ReplayAvailable() {
		t.Error("ReplayAvailable should be true at v2")
	}
	s.Close()

	// Re-open: version stays at 2, no error, buckets still present.
	s2, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer s2.Close()
	if got := s2.SchemaVersion(); got != 2 {
		t.Errorf("re-open SchemaVersion=%d, want 2", got)
	}
}

// TestClusterObservation_RoundTrip writes a few records with different
// timestamps and reads them back through ReadClusterObservationsRange.
// Verifies (a) the time-sorted key encoding, (b) JSON marshalling
// preserves per-station fields, (c) the time-range cursor walks
// correctly.
func TestClusterObservation_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	mk := func(tsNs uint64, from string, pid uint32, n int) *ClusterObservationRecord {
		rec := &ClusterObservationRecord{
			From: from, PacketID: pid,
			ClusterTimeNs:   tsNs,
			FirstSeenWallNs: tsNs + 1_000_000,
			Preset:          "MediumFast",
			SF:              9, CR: 5, BwHz: 250_000,
			FreqHz:      906_875_000,
			ChannelName: "LongFast",
		}
		for i := 0; i < n; i++ {
			rec.Observations = append(rec.Observations, ClusterObservationStation{
				Station:         fmt.Sprintf("sta%d", i),
				StationLat:      39.0 + float64(i)*0.001,
				StationLon:      -98.0,
				StationTNs:      tsNs + 100_000_000,
				StationTAccNs:   1000,
				PreambleLockTNs: tsNs - uint64(i)*10,
				SnrDB:           20.0 - float64(i),
				RssiDB:          -90.0,
			})
		}
		return rec
	}

	recs := []*ClusterObservationRecord{
		mk(1_700_000_000_000_000_000, "!aaaa1111", 100, 3),
		mk(1_700_000_001_000_000_000, "!bbbb2222", 101, 4),
		mk(1_700_000_002_000_000_000, "!cccc3333", 102, 2),
	}
	for _, rec := range recs {
		if err := s.WriteClusterObservation(rec); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if n, _ := s.CountClusterObservations(); n != 3 {
		t.Fatalf("CountClusterObservations=%d, want 3", n)
	}
	got, err := s.ReadClusterObservationsRange(0, ^uint64(0))
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read all len=%d, want 3", len(got))
	}
	for i, want := range recs {
		if got[i].From != want.From || got[i].PacketID != want.PacketID {
			t.Errorf("read[%d] = (%s,%d), want (%s,%d)", i, got[i].From, got[i].PacketID, want.From, want.PacketID)
		}
		if got[i].ClusterTimeNs != want.ClusterTimeNs {
			t.Errorf("read[%d].ClusterTimeNs = %d, want %d", i, got[i].ClusterTimeNs, want.ClusterTimeNs)
		}
		if len(got[i].Observations) != len(want.Observations) {
			t.Errorf("read[%d] stations = %d, want %d", i, len(got[i].Observations), len(want.Observations))
		}
		for j, sw := range want.Observations {
			sg := got[i].Observations[j]
			if sg.Station != sw.Station || sg.StationLat != sw.StationLat || sg.PreambleLockTNs != sw.PreambleLockTNs || sg.SnrDB != sw.SnrDB {
				t.Errorf("read[%d].Observations[%d] = %+v, want match for %+v", i, j, sg, sw)
			}
		}
	}
	got, err = s.ReadClusterObservationsRange(1_700_000_000_500_000_000, 1_700_000_001_500_000_000)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(got) != 1 || got[0].From != "!bbbb2222" {
		t.Errorf("range scan got %+v, want exactly the middle record", got)
	}
}

func TestClusterObservation_NilStore(t *testing.T) {
	var s *EventStore
	if err := s.WriteClusterObservation(&ClusterObservationRecord{From: "!x"}); err != nil {
		t.Errorf("nil store write: got err %v, want nil", err)
	}
	got, err := s.ReadClusterObservationsRange(0, 1)
	if err != nil || len(got) != 0 {
		t.Errorf("nil store read: got %v, %v; want nil, nil", got, err)
	}
	if n, err := s.CountClusterObservations(); n != 0 || err != nil {
		t.Errorf("nil store count: got %d, %v; want 0, nil", n, err)
	}
}

// TestPairSnapshot_RoundTrip writes a sequence of pair snapshots and
// reads them back via both the range-scan and the latest-at-or-before
// lookups.
func TestPairSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	mk := func(tsNs uint64, pair string, median float64) *PairSnapshotRecord {
		return &PairSnapshotRecord{
			PairKey:          pair,
			SnapshotTimeNs:   tsNs,
			LastAnchorTimeNs: tsNs,
			MedianNs:         median,
			MadNs:            12.3,
			SampleCount:      10,
			AnchorIDs:        []string{"!anchor1"},
			StatusAtSnapshot: "converged",
			MaxAgeS:          600.0,
		}
	}
	rows := []*PairSnapshotRecord{
		mk(1_700_000_000_000_000_000, "alpha|bravo", 50_000),
		mk(1_700_000_001_000_000_000, "alpha|bravo", 50_100),
		mk(1_700_000_002_000_000_000, "alpha|bravo", 50_200),
		mk(1_700_000_001_000_000_000, "alpha|delta", -30_000),
	}
	for _, r := range rows {
		if err := s.WritePairSnapshot(r); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if n, _ := s.CountPairSnapshots(); n != 4 {
		t.Fatalf("CountPairSnapshots=%d, want 4", n)
	}

	// Range scan picks up everything in the window.
	got, err := s.ReadPairSnapshotsRange(0, ^uint64(0))
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("range len=%d, want 4", len(got))
	}

	// LatestAtOrBefore for "alpha|bravo" at t=1.5s should be the t=1.0s row.
	rec, ok, err := s.LatestPairSnapshotAtOrBefore(1_700_000_001_500_000_000, "alpha|bravo")
	if err != nil || !ok {
		t.Fatalf("lookup: err=%v ok=%v", err, ok)
	}
	if rec.SnapshotTimeNs != 1_700_000_001_000_000_000 || rec.MedianNs != 50_100 {
		t.Errorf("got rec %+v, want the 50_100 row at t=1s", rec)
	}

	// LatestAtOrBefore for "alpha|delta" at t=10s -> the only delta row.
	rec, ok, err = s.LatestPairSnapshotAtOrBefore(1_700_000_010_000_000_000, "alpha|delta")
	if err != nil || !ok {
		t.Fatalf("delta lookup: err=%v ok=%v", err, ok)
	}
	if rec.PairKey != "alpha|delta" || rec.MedianNs != -30_000 {
		t.Errorf("got rec %+v, want alpha|delta median=-30000", rec)
	}

	// LatestAtOrBefore well before any sample returns ok=false.
	_, ok, err = s.LatestPairSnapshotAtOrBefore(1_699_999_999_000_000_000, "alpha|bravo")
	if err != nil {
		t.Fatalf("pre-window: %v", err)
	}
	if ok {
		t.Errorf("ok=true for query before any sample")
	}

	// LatestAtOrBefore for a pair that never had a snapshot returns ok=false.
	_, ok, err = s.LatestPairSnapshotAtOrBefore(^uint64(0)>>1, "alpha|echo")
	if err != nil {
		t.Fatalf("unknown pair: %v", err)
	}
	if ok {
		t.Errorf("ok=true for unknown pair")
	}
}

// TestPairSnapshot_NilStore covers the no-state-DB path.
func TestPairSnapshot_NilStore(t *testing.T) {
	var s *EventStore
	if err := s.WritePairSnapshot(&PairSnapshotRecord{PairKey: "x|y"}); err != nil {
		t.Errorf("nil write: %v", err)
	}
	rec, ok, err := s.LatestPairSnapshotAtOrBefore(123, "x|y")
	if err != nil || ok || rec != nil {
		t.Errorf("nil lookup: rec=%v ok=%v err=%v", rec, ok, err)
	}
	rows, err := s.ReadPairSnapshotsRange(0, 1)
	if err != nil || len(rows) != 0 {
		t.Errorf("nil range: rows=%v err=%v", rows, err)
	}
	if n, err := s.CountPairSnapshots(); n != 0 || err != nil {
		t.Errorf("nil count: %d %v", n, err)
	}
}

// TestPairSnapshot_FeedClusterEmits ensures FeedCluster returns one
// PairSnapshotRecord per touched pair when an anchor cluster lands.
func TestPairSnapshot_FeedClusterEmits(t *testing.T) {
	sc := newScene(t, 0)
	c := sc.mkAnchorCluster(1, 1_700_000_000_000_000_000, map[string]float64{
		"alpha": 0, "bravo": 50_000, "delta": -30_000,
	})
	got := sc.cs.FeedCluster(c)
	// 3 stations -> 3 unique pairs touched.
	if len(got) != 3 {
		t.Fatalf("FeedCluster returned %d records, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.PairKey] = true
		// snapshot_time_ns must be the max PreambleLockTNs in the cluster.
		// We injected base+propagation; verify it's >= base.
		if r.SnapshotTimeNs < 1_700_000_000_000_000_000 {
			t.Errorf("snapshot_time_ns=%d, want >= base txTime", r.SnapshotTimeNs)
		}
		// anchor_ids should contain the anchor we declared.
		if len(r.AnchorIDs) != 1 || r.AnchorIDs[0] != sc.anchor.NodeID {
			t.Errorf("anchor_ids=%v, want [%s]", r.AnchorIDs, sc.anchor.NodeID)
		}
	}
	for _, want := range []string{"alpha|bravo", "alpha|delta", "bravo|delta"} {
		if !seen[want] {
			t.Errorf("missing pair %s in FeedCluster output", want)
		}
	}
	// Non-anchor cluster returns no snapshots.
	spoof := &Cluster{Frame: Frame{From: "!notanchor", PacketID: 99}}
	for _, st := range sc.stations {
		spoof.Observations = append(spoof.Observations, Observation{
			Station: st.Name, StationLat: st.Lat, StationLon: st.Lon,
			PreambleLockTNs: 1_700_000_000_500_000_000,
			RssiDB:          -90.0,
		})
	}
	if got := sc.cs.FeedCluster(spoof); len(got) != 0 {
		t.Errorf("non-anchor cluster returned %d records, want 0", len(got))
	}
}
