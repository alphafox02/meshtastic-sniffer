// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// HTTP API endpoint tests via httptest. Exercises the same handlers
// the live server registers so a regression in routing or auth is
// caught here, not from a 401-storm in production.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newAPIHandler builds the same wrapped /api/* mux that startWebServer
// installs, plus an open / handler. Lets tests hit the real mux
// without spinning up a TCP listener. `store` may be nil for tests
// that don't care about evidence endpoints.
func newAPIHandler(t *testing.T, registry *Registry, hub *SSEHub, apiToken string) http.Handler {
	return newAPIHandlerWithStore(t, registry, hub, nil, apiToken)
}

func newAPIHandlerWithStore(t *testing.T, registry *Registry, hub *SSEHub, store *EventStore, apiToken string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/sensors", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(registry.List())
		case http.MethodPost:
			var s Sensor
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				jsonError(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if err := registry.Add(&s); err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			jsonOK(w, map[string]string{"added": s.Name})
		default:
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	apiMux.HandleFunc("/api/sensors/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path[len("/api/sensors/"):]
		if name == "" {
			jsonError(w, "missing name", http.StatusBadRequest)
			return
		}
		if err := registry.Remove(name); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"removed": name})
	})
	// Mirrors startWebServer's /api/clock-sync/warnings handler so the
	// route is exercised under the same auth wrap as the real server.
	apiMux.HandleFunc("/api/clock-sync/warnings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		warnings := []ClockSyncWarning{}
		if globalClockSync != nil {
			warnings = globalClockSync.AnchorWarnings()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":  globalClockSync != nil,
			"warnings": warnings,
		})
	})
	// Evidence endpoints mirror the real server. store may be nil; the
	// handlers degrade to persisted=false + empty record lists.
	apiMux.HandleFunc("/api/evidence/clusters", evidenceClustersHandler(store))
	apiMux.HandleFunc("/api/evidence/pairs", evidencePairsHandler(store))
	apiMux.HandleFunc("/api/evidence/fixes", evidenceFixesHandler(store))
	apiMux.HandleFunc("/api/evidence/summary", evidenceSummaryHandler(store))
	apiMux.HandleFunc("/api/resolve", resolveHandler(store, hub))
	wrapped := authWrap(apiMux, apiToken)
	mux.Handle("/api/", wrapped)
	mux.Handle("/events", wrapped)
	return mux
}

func newTestRegistryUnauthed(t *testing.T) *Registry {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r, err := NewRegistry(ctx, dir+"/sensors.json", nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestAPI_GetSensorsEmpty(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("body=%q want []", body)
	}
}

func TestAPI_AddSensorAndList(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	post := httptest.NewRequest(http.MethodPost, "/api/sensors",
		strings.NewReader(`{"name":"alpha","zmq":"tcp://127.0.0.1:7008"}`))
	post.Header.Set("Content-Type", "application/json")
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, post)
	if pw.Code != http.StatusOK {
		t.Fatalf("POST status=%d body=%s", pw.Code, pw.Body.String())
	}
	get := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	gw := httptest.NewRecorder()
	h.ServeHTTP(gw, get)
	var list []Sensor
	if err := json.Unmarshal(gw.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list) != 1 || list[0].Name != "alpha" {
		t.Fatalf("list=%+v", list)
	}
}

func TestAPI_DeleteSensor(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	_ = r.Add(&Sensor{Name: "to-delete", Zmq: "tcp://x:1"})
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/to-delete", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if list := r.List(); len(list) != 0 {
		t.Fatalf("post-delete list=%+v want empty", list)
	}
}

func TestAPI_DeleteUnknownIs404(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/ghost", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", w.Code)
	}
}

func TestAPI_AuthBlocksApiButNotIndex(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "secret123")

	// / always open
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/ status=%d want 200 even with auth on", w.Code)
	}

	// /api/sensors blocked
	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/api/sensors status=%d want 401", w.Code)
	}

	// /api/sensors with bearer accepted
	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/api/sensors with bearer status=%d want 200", w.Code)
	}
}

func TestAPI_BadPostBodyIs400(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/sensors", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestAPI_AddSensorMissingFieldsIs400(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/sensors",
		strings.NewReader(`{"name":"missing-zmq"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (sensor needs zmq endpoint)", w.Code)
	}
}

// withGlobalClockSync swaps the package-level globalClockSync for the
// duration of one test and restores it on cleanup. Lets the endpoint
// tests exercise the disabled / enabled / warning-bearing states without
// leaking state into the next test.
func withGlobalClockSync(t *testing.T, cs *ClockSync) {
	t.Helper()
	prev := globalClockSync
	globalClockSync = cs
	t.Cleanup(func() { globalClockSync = prev })
}

// TestAPI_ClockSyncWarnings_Disabled: when fusion runs with
// --clock-sync=off (globalClockSync == nil), the endpoint must still
// answer 200 with enabled=false and empty warnings list.
func TestAPI_ClockSyncWarnings_Disabled(t *testing.T) {
	withGlobalClockSync(t, nil)
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/clock-sync/warnings", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	var got struct {
		Enabled  bool               `json:"enabled"`
		Warnings []ClockSyncWarning `json:"warnings"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v -- body=%s", err, body)
	}
	if got.Enabled {
		t.Errorf("enabled=true with nil globalClockSync")
	}
	if got.Warnings == nil || len(got.Warnings) != 0 {
		t.Errorf("warnings=%v, want []", got.Warnings)
	}
}

// TestAPI_ClockSyncWarnings_Empty: clock-sync enabled but no warnings
// retained (e.g. anchors all placed at safe distances). Must report
// enabled=true with empty warnings list.
func TestAPI_ClockSyncWarnings_Empty(t *testing.T) {
	cs := NewClockSync(DefaultClockSyncConfig())
	withGlobalClockSync(t, cs)
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/clock-sync/warnings", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Enabled  bool               `json:"enabled"`
		Warnings []ClockSyncWarning `json:"warnings"`
	}
	_ = json.NewDecoder(w.Body).Decode(&got)
	if !got.Enabled {
		t.Errorf("enabled=false with non-nil globalClockSync")
	}
	if got.Warnings == nil || len(got.Warnings) != 0 {
		t.Errorf("warnings=%v, want []", got.Warnings)
	}
}

// TestAPI_ClockSyncWarnings_Populated: warnings retained via
// SetAnchorWarnings appear verbatim in the response body.
func TestAPI_ClockSyncWarnings_Populated(t *testing.T) {
	cs := NewClockSync(DefaultClockSyncConfig())
	cs.SetAnchorWarnings([]ClockSyncWarning{{
		Code:        "anchor_too_close",
		AnchorID:    "!aaaa",
		StationName: "rooftop",
		DistanceM:   12.3,
		MinM:        30.0,
		Message:     "anchor !aaaa is 12.3 m from sniffer station \"rooftop\" (<30 m)",
	}})
	withGlobalClockSync(t, cs)

	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/clock-sync/warnings", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Enabled  bool               `json:"enabled"`
		Warnings []ClockSyncWarning `json:"warnings"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Enabled {
		t.Errorf("enabled=false; want true")
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings len=%d, want 1: %+v", len(got.Warnings), got.Warnings)
	}
	wn := got.Warnings[0]
	if wn.Code != "anchor_too_close" || wn.AnchorID != "!aaaa" || wn.StationName != "rooftop" {
		t.Errorf("warning fields mismatch: %+v", wn)
	}
	if wn.DistanceM != 12.3 || wn.MinM != 30.0 {
		t.Errorf("warning distances mismatch: %+v", wn)
	}
}

// TestAPI_ClockSyncWarnings_MethodNotAllowed: POST / DELETE / etc must
// return 405. Operator can read but not mutate the list.
func TestAPI_ClockSyncWarnings_MethodNotAllowed(t *testing.T) {
	withGlobalClockSync(t, NewClockSync(DefaultClockSyncConfig()))
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/clock-sync/warnings",
		strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

// openTestStore opens a fresh bbolt store in t.TempDir; t.Cleanup
// closes it. Used by the Evidence-endpoint tests so each test owns its
// own DB file and round-trips real records through the handlers.
func openTestStore(t *testing.T) *EventStore {
	t.Helper()
	path := t.TempDir() + "/state.db"
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("OpenEventStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestAPI_Evidence_Summary_NilStore exercises the no-state-db case:
// every count is zero, persisted=false, schema_version=0.
func TestAPI_Evidence_Summary_NilStore(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/summary", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Persisted       bool           `json:"persisted"`
		SchemaVersion   int            `json:"schema_version"`
		ReplayAvailable bool           `json:"replay_available"`
		Counts          map[string]int `json:"counts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&got)
	if got.Persisted {
		t.Errorf("persisted=true with nil store")
	}
	if got.SchemaVersion != 0 || got.ReplayAvailable {
		t.Errorf("nil store should report schema_version=0 / replay_available=false; got %+v", got)
	}
	for k, v := range got.Counts {
		if v != 0 {
			t.Errorf("count[%s]=%d, want 0", k, v)
		}
	}
}

// TestAPI_Evidence_Summary_Populated writes one of each record type and
// confirms the summary counts pick them up.
func TestAPI_Evidence_Summary_Populated(t *testing.T) {
	s := openTestStore(t)
	if err := s.WriteClusterObservation(&ClusterObservationRecord{
		From: "!a", PacketID: 1, ClusterTimeNs: 100,
	}); err != nil {
		t.Fatalf("write cluster: %v", err)
	}
	if err := s.WritePairSnapshot(&PairSnapshotRecord{
		PairKey: "a|b", SnapshotTimeNs: 100,
	}); err != nil {
		t.Fatalf("write pair: %v", err)
	}
	if err := s.WriteSolvedFix(&SolvedFixRecord{
		From: "!a", PacketID: 1, EventTimeNs: 100,
	}); err != nil {
		t.Fatalf("write fix: %v", err)
	}
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, s, "")
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/summary", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Persisted       bool           `json:"persisted"`
		SchemaVersion   int            `json:"schema_version"`
		ReplayAvailable bool           `json:"replay_available"`
		Counts          map[string]int `json:"counts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&got)
	if !got.Persisted || got.SchemaVersion < 3 || !got.ReplayAvailable {
		t.Errorf("populated store: persisted=%v schema=%d replay=%v",
			got.Persisted, got.SchemaVersion, got.ReplayAvailable)
	}
	for _, k := range []string{"cluster_observations", "pair_snapshots", "solved_fixes"} {
		if got.Counts[k] != 1 {
			t.Errorf("counts[%s]=%d, want 1", k, got.Counts[k])
		}
	}
}

// TestAPI_Evidence_Clusters_RoundTrip writes three cluster records at
// known times and verifies the range query bounds.
func TestAPI_Evidence_Clusters_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	for i, ts := range []uint64{1_000_000_000, 2_000_000_000, 3_000_000_000} {
		if err := s.WriteClusterObservation(&ClusterObservationRecord{
			From: "!a", PacketID: uint32(i), ClusterTimeNs: ts,
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, s, "")

	// Default range = last hour, ending now. All three fall in the past
	// (the timestamps above are in 1970-1971); they should NOT appear.
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/clusters", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("default range status=%d want 200", w.Code)
	}
	var def struct {
		Persisted bool                       `json:"persisted"`
		Count     int                        `json:"count"`
		Records   []ClusterObservationRecord `json:"records"`
	}
	_ = json.NewDecoder(w.Body).Decode(&def)
	if !def.Persisted {
		t.Errorf("persisted=false; want true (store provided)")
	}
	if def.Count != 0 {
		t.Errorf("default range got %d records; want 0 (timestamps in 1970)", def.Count)
	}

	// Explicit range that brackets the second record only.
	req = httptest.NewRequest(http.MethodGet,
		"/api/evidence/clusters?start_ns=1500000000&end_ns=2500000000", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("range status=%d want 200", w.Code)
	}
	var rng struct {
		Count   int                        `json:"count"`
		Records []ClusterObservationRecord `json:"records"`
	}
	_ = json.NewDecoder(w.Body).Decode(&rng)
	if rng.Count != 1 || rng.Records[0].ClusterTimeNs != 2_000_000_000 {
		t.Errorf("range scan got %d records (first=%+v); want exactly the middle record",
			rng.Count, rng.Records)
	}
}

// TestAPI_Evidence_Fixes_RoundTrip mirrors the clusters test with the
// solved_fixes bucket so the fixes endpoint's encoding is exercised.
func TestAPI_Evidence_Fixes_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	if err := s.WriteSolvedFix(&SolvedFixRecord{
		EventTimeNs: 2_000_000_000, From: "!a", PacketID: 1, Lat: 39, Lon: -98, UncertaintyM: 5,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, s, "")
	req := httptest.NewRequest(http.MethodGet,
		"/api/evidence/fixes?start_ns=1000000000&end_ns=3000000000", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Count   int               `json:"count"`
		Records []SolvedFixRecord `json:"records"`
	}
	_ = json.NewDecoder(w.Body).Decode(&got)
	if got.Count != 1 || got.Records[0].UncertaintyM != 5 {
		t.Errorf("fixes range got %+v; want one record uncertainty=5", got)
	}
}

// newAPIHandlerWithHub mirrors newAPIHandlerWithStore but also wires a
// real SSEHub so the resolve endpoint can publish REPLAY_GEOLOCATED.
func newAPIHandlerWithHub(t *testing.T, registry *Registry, hub *SSEHub, store *EventStore, apiToken string) http.Handler {
	return newAPIHandlerWithStore(t, registry, hub, store, apiToken)
}

// drainHubHistory reads everything currently in the hub's history ring.
// Used in resolve tests to verify the REPLAY_GEOLOCATED event hit the
// publisher path without spinning up a real /events SSE client.
func drainHubHistory(hub *SSEHub) [][]byte {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	out := make([][]byte, 0, hub.histLen)
	start := 0
	if hub.histLen == sseHistorySize {
		start = hub.histHead
	}
	for i := 0; i < hub.histLen; i++ {
		idx := (start + i) % sseHistorySize
		if hub.history[idx] != nil {
			out = append(out, hub.history[idx])
		}
	}
	return out
}

// seedResolveFixture writes one cluster_observations row + two pair
// snapshots into the store so a /api/resolve event_time call has
// something to chew on. Returns the event_time_ns it wrote at.
func seedResolveFixture(t *testing.T, s *EventStore) uint64 {
	t.Helper()
	const eventNs = uint64(1_780_000_000_000_000_000)
	rec := &ClusterObservationRecord{
		From: "!aabbccdd", PacketID: 100, EmissionSeq: 0,
		ClusterTimeNs:   eventNs,
		FirstSeenWallNs: eventNs + 1_000,
		Preset:          "MediumFast",
		Observations: []ClusterObservationStation{
			{
				Station: "alpha", StationLat: 39.010, StationLon: -98.010,
				StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000,
				PreambleLockTNs: eventNs, SnrDB: 8,
			},
			{
				Station: "bravo", StationLat: 39.000, StationLon: -98.012,
				StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000,
				PreambleLockTNs: eventNs + 20_000, SnrDB: 6,
			},
			{
				Station: "delta", StationLat: 38.988, StationLon: -98.002,
				StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000,
				PreambleLockTNs: eventNs + 25_000, SnrDB: 7,
			},
		},
	}
	if err := s.WriteClusterObservation(rec); err != nil {
		t.Fatalf("seed cluster: %v", err)
	}
	for _, ps := range []*PairSnapshotRecord{
		{
			PairKey: "alpha|bravo", SnapshotTimeNs: eventNs,
			LastAnchorTimeNs: eventNs - 1_000_000_000,
			MedianNs:         20_000, MadNs: 500, SampleCount: 12,
			AnchorIDs:        []string{"!cafe"},
			StatusAtSnapshot: "converged",
			MaxAgeS:          600,
		},
		{
			PairKey: "alpha|delta", SnapshotTimeNs: eventNs,
			LastAnchorTimeNs: eventNs - 1_000_000_000,
			MedianNs:         25_000, MadNs: 600, SampleCount: 11,
			AnchorIDs:        []string{"!cafe"},
			StatusAtSnapshot: "converged",
			MaxAgeS:          600,
		},
	} {
		if err := s.WritePairSnapshot(ps); err != nil {
			t.Fatalf("seed pair: %v", err)
		}
	}
	return eventNs
}

// TestAPI_Resolve_EventTime_StaleSnapshotNotApplied: when the only
// pair snapshot at or before the event time is older than MaxAgeS,
// event-time replay must NOT apply it. The result class should fall
// back to software_lock instead of falsely labeling sync. Catches a
// past bug where StatusAtSnapshot=="converged" alone was enough to
// apply the offset, even on snapshots that should have aged out.
func TestAPI_Resolve_EventTime_StaleSnapshotNotApplied(t *testing.T) {
	s := openTestStore(t)
	const eventNs = uint64(1_780_000_000_000_000_000)
	rec := &ClusterObservationRecord{
		From: "!aabbccdd", PacketID: 100, EmissionSeq: 0,
		ClusterTimeNs:   eventNs,
		FirstSeenWallNs: eventNs + 1_000,
		Preset:          "MediumFast",
		Observations: []ClusterObservationStation{
			{Station: "alpha", StationLat: 39.010, StationLon: -98.010, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs, SnrDB: 8},
			{Station: "bravo", StationLat: 39.000, StationLon: -98.012, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs + 20_000, SnrDB: 6},
			{Station: "delta", StationLat: 38.988, StationLon: -98.002, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs + 25_000, SnrDB: 7},
		},
	}
	if err := s.WriteClusterObservation(rec); err != nil {
		t.Fatalf("seed cluster: %v", err)
	}
	// Snapshots converged but their snapshot_time is 1 hour BEFORE the
	// event, while MaxAgeS is only 600 s -> they were stale at the
	// target event time and must NOT be applied.
	staleSnapshotNs := eventNs - uint64(3600*time.Second)
	for _, ps := range []*PairSnapshotRecord{
		{PairKey: "alpha|bravo", SnapshotTimeNs: staleSnapshotNs, LastAnchorTimeNs: staleSnapshotNs, MedianNs: 20_000, MadNs: 500, SampleCount: 12, AnchorIDs: []string{"!cafe"}, StatusAtSnapshot: "converged", MaxAgeS: 600},
		{PairKey: "alpha|delta", SnapshotTimeNs: staleSnapshotNs, LastAnchorTimeNs: staleSnapshotNs, MedianNs: 25_000, MadNs: 600, SampleCount: 11, AnchorIDs: []string{"!cafe"}, StatusAtSnapshot: "converged", MaxAgeS: 600},
	} {
		if err := s.WritePairSnapshot(ps); err != nil {
			t.Fatalf("seed pair: %v", err)
		}
	}

	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")
	body := fmt.Sprintf(`{"from":"!aabbccdd","packet_id":100,"emission_seq":0,"event_time_ns":%d,"mode":"event_time"}`, eventNs)
	req := httptest.NewRequest(http.MethodPost, "/api/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	pubs := drainHubHistory(hub)
	if len(pubs) != 1 {
		t.Fatalf("hub got %d events, want 1", len(pubs))
	}
	var ev replayEvent
	if err := json.Unmarshal(pubs[0], &ev); err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	if ev.TimestampClass == "sync" {
		t.Errorf("timestamp_class=sync with snapshots aged %ds past MaxAgeS=600s; should fall back to software_lock",
			3600-600)
	}
	if len(ev.PairSnapshotKeysUsed) != 0 {
		t.Errorf("pair_snapshot_keys_used=%v; stale snapshots must not be applied", ev.PairSnapshotKeysUsed)
	}
}

// TestAPI_Resolve_Happy: seeded cluster + pair snapshots, POST resolve,
// expect 200 + REPLAY_GEOLOCATED on the hub with correct source/mode/
// clock_model_time_ns fields and a sane solve.
func TestAPI_Resolve_Happy(t *testing.T) {
	s := openTestStore(t)
	eventNs := seedResolveFixture(t, s)
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")

	body := fmt.Sprintf(`{"from":"!aabbccdd","packet_id":100,"emission_seq":0,"event_time_ns":%d,"mode":"event_time"}`, eventNs)
	req := httptest.NewRequest(http.MethodPost, "/api/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var ack struct {
		Queued        bool   `json:"queued"`
		SourceEventID string `json:"source_event_id"`
	}
	_ = json.NewDecoder(w.Body).Decode(&ack)
	if !ack.Queued {
		t.Errorf("queued=false")
	}
	wantID := fmt.Sprintf("!aabbccdd|100|0|%d", eventNs)
	if ack.SourceEventID != wantID {
		t.Errorf("source_event_id=%q want %q", ack.SourceEventID, wantID)
	}

	pubs := drainHubHistory(hub)
	if len(pubs) != 1 {
		t.Fatalf("hub got %d events, want 1", len(pubs))
	}
	var ev replayEvent
	if err := json.Unmarshal(pubs[0], &ev); err != nil {
		t.Fatalf("decode pub: %v -- raw=%s", err, pubs[0])
	}
	if ev.Event != "REPLAY_GEOLOCATED" {
		t.Errorf("event=%q want REPLAY_GEOLOCATED", ev.Event)
	}
	if ev.SourceEventID != wantID {
		t.Errorf("event.source_event_id=%q want %q", ev.SourceEventID, wantID)
	}
	if ev.ReplayMode != "event_time" {
		t.Errorf("replay_mode=%q want event_time", ev.ReplayMode)
	}
	if ev.ClockModelTimeNs != eventNs {
		t.Errorf("clock_model_time_ns=%d want %d", ev.ClockModelTimeNs, eventNs)
	}
	if ev.StationCount != 3 {
		t.Errorf("station_count=%d want 3", ev.StationCount)
	}
	if ev.TimestampClass != "sync" {
		t.Errorf("timestamp_class=%q want sync (snapshots are converged)", ev.TimestampClass)
	}
}

// TestAPI_Resolve_EventNotFound: cluster_observations row for the given
// composite key doesn't exist -> 404.
func TestAPI_Resolve_EventNotFound(t *testing.T) {
	s := openTestStore(t)
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")

	req := httptest.NewRequest(http.MethodPost, "/api/resolve",
		strings.NewReader(`{"from":"!missing","packet_id":1,"event_time_ns":12345,"mode":"event_time"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404; body=%s", w.Code, w.Body.String())
	}
}

// TestAPI_Resolve_NoStateDB: store is nil -> 503 (replay needs persistence).
func TestAPI_Resolve_NoStateDB(t *testing.T) {
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/resolve",
		strings.NewReader(`{"from":"!a","packet_id":1,"event_time_ns":1,"mode":"event_time"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503", w.Code)
	}
}

// TestAPI_Resolve_CurrentModel_Happy: same seeded fixture as Happy, but
// mode=current_model. The handler should route to the live clock-sync
// path; the SSE event must carry replay_mode=current_model, an advisory
// string warning that this is NOT a clean replay, and a recent
// clock_model_time_ns (wall-clock when the resolve ran, not the event).
func TestAPI_Resolve_CurrentModel_Happy(t *testing.T) {
	// globalClockSync needs to exist for current_model. We don't need it
	// to actually converge for this test; resolveWithCurrentModel falls
	// back to a lex-smallest reference when PickReferenceStation returns
	// empty. The solver then runs with software_lock-class observations
	// and still produces a fix.
	withGlobalClockSync(t, NewClockSync(DefaultClockSyncConfig()))
	s := openTestStore(t)
	eventNs := seedResolveFixture(t, s)
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")

	body := fmt.Sprintf(`{"from":"!aabbccdd","packet_id":100,"emission_seq":0,"event_time_ns":%d,"mode":"current_model"}`, eventNs)
	req := httptest.NewRequest(http.MethodPost, "/api/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}

	pubs := drainHubHistory(hub)
	if len(pubs) != 1 {
		t.Fatalf("hub got %d events, want 1", len(pubs))
	}
	var ev replayEvent
	if err := json.Unmarshal(pubs[0], &ev); err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	if ev.ReplayMode != "current_model" {
		t.Errorf("replay_mode=%q want current_model", ev.ReplayMode)
	}
	if ev.Advisory == "" {
		t.Errorf("advisory must be set on current_model replay")
	}
	if !strings.Contains(strings.ToLower(ev.Advisory), "not a clean replay") {
		t.Errorf("advisory should warn about clean-replay; got %q", ev.Advisory)
	}
	// clock_model_time_ns is wall-clock-now, NOT event_time_ns.
	if ev.ClockModelTimeNs == eventNs {
		t.Errorf("clock_model_time_ns should differ from event_time_ns in current_model mode; got %d", ev.ClockModelTimeNs)
	}
	if ev.StationCount != 3 {
		t.Errorf("station_count=%d want 3", ev.StationCount)
	}
}

// TestAPI_Resolve_AcceptsStringEventTimeNs: the resolve endpoint must
// accept event_time_ns as a JSON string so callers can preserve full
// 64-bit precision through environments (browsers, JS-based clients,
// some JSON parsers) that round numbers past Number.MAX_SAFE_INTEGER.
// Picks an event_time_ns with non-zero low bits below 2^53 so the
// rounded form would differ from the exact form -- proves the handler
// is not silently re-parsing through a float.
func TestAPI_Resolve_AcceptsStringEventTimeNs(t *testing.T) {
	s := openTestStore(t)
	const eventNs = uint64(1_770_000_000_000_000_123)
	rec := &ClusterObservationRecord{
		From: "!stringevt", PacketID: 7, EmissionSeq: 0,
		ClusterTimeNs:   eventNs,
		FirstSeenWallNs: eventNs + 1,
		Preset:          "MediumFast",
		Observations: []ClusterObservationStation{
			{Station: "alpha", StationLat: 39.010, StationLon: -98.010, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs, SnrDB: 8},
			{Station: "bravo", StationLat: 39.000, StationLon: -98.012, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs + 20_000, SnrDB: 6},
			{Station: "delta", StationLat: 38.988, StationLon: -98.002, StationTNs: eventNs + 5_000_000, StationTAccNs: 1_000_000, PreambleLockTNs: eventNs + 25_000, SnrDB: 7},
		},
	}
	if err := s.WriteClusterObservation(rec); err != nil {
		t.Fatalf("seed cluster: %v", err)
	}
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")

	// String form -- this is what the UI now sends.
	body := fmt.Sprintf(`{"from":"!stringevt","packet_id":7,"emission_seq":0,"event_time_ns":"%d","mode":"event_time"}`, eventNs)
	req := httptest.NewRequest(http.MethodPost, "/api/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("string form status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var ack struct {
		SourceEventID string `json:"source_event_id"`
	}
	_ = json.NewDecoder(w.Body).Decode(&ack)
	wantID := fmt.Sprintf("!stringevt|7|0|%d", eventNs)
	if ack.SourceEventID != wantID {
		t.Errorf("source_event_id=%q want %q (event_time_ns lost precision through string round-trip)", ack.SourceEventID, wantID)
	}

	// Numeric form must also still work for older clients.
	body2 := fmt.Sprintf(`{"from":"!stringevt","packet_id":7,"emission_seq":0,"event_time_ns":%d,"mode":"event_time"}`, eventNs)
	req2 := httptest.NewRequest(http.MethodPost, "/api/resolve", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("numeric form status=%d want 200; body=%s", w2.Code, w2.Body.String())
	}
}

// TestAPI_Evidence_ClusterTimeNsS_Populated: the clusters endpoint
// must include a string-form cluster_time_ns_s alongside the numeric
// cluster_time_ns so the browser has a precision-preserving handle.
func TestAPI_Evidence_ClusterTimeNsS_Populated(t *testing.T) {
	s := openTestStore(t)
	const ts = uint64(1_770_000_000_000_000_123)
	if err := s.WriteClusterObservation(&ClusterObservationRecord{
		From: "!a", PacketID: 1, ClusterTimeNs: ts,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, s, "")
	q := fmt.Sprintf("?start_ns=%d&end_ns=%d", ts-1, ts+1)
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/clusters"+q, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var got struct {
		Records []ClusterObservationRecord `json:"records"`
	}
	_ = json.NewDecoder(w.Body).Decode(&got)
	if len(got.Records) != 1 {
		t.Fatalf("records=%d want 1", len(got.Records))
	}
	wantS := fmt.Sprintf("%d", ts)
	if got.Records[0].ClusterTimeNsS != wantS {
		t.Errorf("cluster_time_ns_s=%q want %q", got.Records[0].ClusterTimeNsS, wantS)
	}
}

// TestAPI_Resolve_BadInputs: missing fields -> 400; bad JSON -> 400;
// unknown mode -> 400; wrong method -> 405.
func TestAPI_Resolve_BadInputs(t *testing.T) {
	s := openTestStore(t)
	hub := newSSEHub()
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithHub(t, r, hub, s, "")
	cases := []struct {
		name string
		method, body string
		want int
	}{
		{"wrong method", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"bad JSON", http.MethodPost, "{this is not json", http.StatusBadRequest},
		{"missing fields", http.MethodPost, `{"mode":"event_time"}`, http.StatusBadRequest},
		{"missing event_time_ns", http.MethodPost, `{"from":"!a","packet_id":1,"mode":"event_time"}`, http.StatusBadRequest},
		{"unknown mode", http.MethodPost, `{"from":"!a","packet_id":1,"event_time_ns":1,"mode":"future_mode"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var bodyR io.Reader
			if c.body != "" {
				bodyR = strings.NewReader(c.body)
			}
			req := httptest.NewRequest(c.method, "/api/resolve", bodyR)
			if c.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != c.want {
				b, _ := io.ReadAll(w.Body)
				t.Errorf("%s status=%d want %d; body=%s", c.name, w.Code, c.want, b)
			}
		})
	}
}

// TestAPI_Evidence_BadRange returns 400 when start_ns can't parse or is
// after end_ns.
func TestAPI_Evidence_BadRange(t *testing.T) {
	s := openTestStore(t)
	r := newTestRegistryUnauthed(t)
	h := newAPIHandlerWithStore(t, r, nil, s, "")
	for _, q := range []string{
		"?start_ns=notanumber",
		"?start_ns=100&end_ns=50",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/clusters"+q, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			b, _ := io.ReadAll(w.Body)
			t.Errorf("range %q status=%d want 400; body=%s", q, w.Code, b)
		}
	}
}
