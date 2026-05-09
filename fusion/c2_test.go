// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSensorServer captures the HTTP fan-out hits. Records the path,
// body, and Authorization header of each request so tests can assert
// the wire-level behavior.
type fakeSensorHit struct {
	Path string
	Body string
	Auth string
}

func newFakeSensor(t *testing.T, hits *atomic.Int64, sink chan<- fakeSensorHit, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		sink <- fakeSensorHit{Path: r.URL.Path, Body: string(body), Auth: r.Header.Get("Authorization")}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return httptest.NewServer(mux)
}

func TestFanout_HTTPHitsEverySensor(t *testing.T) {
	hits := &atomic.Int64{}
	sink := make(chan fakeSensorHit, 16)
	srvA := newFakeSensor(t, hits, sink, 200)
	defer srvA.Close()
	srvB := newFakeSensor(t, hits, sink, 200)
	defer srvB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "sensors.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := NewRegistry(ctx, path, nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	_ = r.Add(&Sensor{Name: "a", Zmq: "tcp://127.0.0.1:1", Api: srvA.URL, ApiToken: "tokA"})
	_ = r.Add(&Sensor{Name: "b", Zmq: "tcp://127.0.0.1:2", Api: srvB.URL})

	results := fanoutCommand(r, "keys", []byte("hex:abcd"))
	if len(results) != 2 {
		t.Fatalf("results len=%d want 2", len(results))
	}
	for _, res := range results {
		if res.Status != 200 {
			t.Errorf("sensor %s: status=%d body=%q err=%q", res.Sensor, res.Status, res.Body, res.Error)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits=%d want 2", got)
	}
	close(sink)

	gotPaths := map[string]bool{}
	authA := ""
	for h := range sink {
		gotPaths[h.Path] = true
		if h.Body != "hex:abcd" {
			t.Errorf("hit body=%q want %q", h.Body, "hex:abcd")
		}
		if strings.Contains(h.Auth, "tokA") {
			authA = h.Auth
		}
	}
	if !gotPaths["/api/keys"] {
		t.Fatalf("did not POST to /api/keys; saw %v", gotPaths)
	}
	if authA != "Bearer tokA" {
		t.Fatalf("sensor a got Authorization=%q, want 'Bearer tokA'", authA)
	}
}

func TestFanout_NoApiEndpointReports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensors.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := NewRegistry(ctx, path, nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	_ = r.Add(&Sensor{Name: "no-api", Zmq: "tcp://127.0.0.1:1"})
	results := fanoutCommand(r, "keys", []byte("hex:00"))
	if len(results) != 1 {
		t.Fatalf("results len=%d want 1", len(results))
	}
	if results[0].Error == "" {
		t.Fatalf("expected non-empty Error for no-api sensor; got %+v", results[0])
	}
}

func TestDealerHub_PercentilesAndRingSnapshot(t *testing.T) {
	// percentiles on empty
	if p50, p95 := percentiles(nil); p50 != 0 || p95 != 0 {
		t.Fatalf("empty percentiles=(%d,%d) want (0,0)", p50, p95)
	}
	// percentiles on small set
	xs := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	p50, p95 := percentiles(xs)
	if p50 != 60 {
		t.Errorf("p50=%d want 60", p50)
	}
	if p95 != 100 {
		t.Errorf("p95=%d want 100", p95)
	}

	// ring snapshot: head at 2 means the ring was filled at indices 0,1
	// most-recently and 2,3 least-recently. Empty (0) slots should be
	// skipped.
	buf := []int64{30, 40, 0, 0, 10, 20}
	got := ringSnapshot(buf, 4)
	want := []int64{10, 20, 30, 40}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("snapshot[%d]=%d want %d", i, got[i], want[i])
		}
	}
}

func TestDealerHub_StatsForUnknownIdentity(t *testing.T) {
	d := &DealerHub{
		sessions: map[string]*dealerSession{},
		pending:  map[int64]chan dealerReply{},
	}
	if got := d.HasSession("ghost"); got {
		t.Errorf("HasSession(ghost) = true; want false")
	}
	if stats := d.Stats(); len(stats) != 0 {
		t.Errorf("Stats() = %+v; want empty", stats)
	}
}

func TestDealerHub_TouchSessionRecordsHeartbeat(t *testing.T) {
	d := &DealerHub{
		sessions: map[string]*dealerSession{},
		pending:  map[int64]chan dealerReply{},
	}
	d.touchSession("rooftop")
	d.touchSession("rooftop")
	stats := d.Stats()
	if len(stats) != 1 {
		t.Fatalf("len(stats)=%d want 1", len(stats))
	}
	if stats[0].Heartbeats != 2 {
		t.Errorf("Heartbeats=%d want 2", stats[0].Heartbeats)
	}
}
