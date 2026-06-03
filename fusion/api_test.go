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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
