// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/web.go: HTTP + SSE server.
//
// When --listen=:PORT is set, fusion serves an empty placeholder index
// (the embedded dashboard HTML lands in a follow-up commit) and an
// /events SSE endpoint that streams the live event firehose -- every
// JSON line received from any subscribed sniffer, plus the consolidated
// TX events fusion emits per (from, packet_id) cluster.
//
// Each sniffer-side event already carries a 'station' field (set via
// --station-id), so the dashboard JS can render multi-station context
// directly off the event stream without any fusion-side reshaping.

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// SSEHub broadcasts byte slices to all currently-connected clients.
// Each client gets its own buffered channel; slow clients are dropped
// when the buffer fills, so a frozen browser can't stall the publisher.
//
// Maintains a bounded ring of recent events. New clients get the ring's
// contents replayed before going live so a browser refresh / new tab
// reconstructs dashboard state without waiting for new traffic.
const sseHistorySize = 1024

type SSEHub struct {
	mu       sync.Mutex
	clients  map[chan []byte]struct{}
	history  [][]byte
	histHead int // index of next slot to write
	histLen  int // total entries currently stored, capped at sseHistorySize
	store    *EventStore // optional: durable mirror of history
}

func newSSEHub() *SSEHub {
	return &SSEHub{
		clients: map[chan []byte]struct{}{},
		history: make([][]byte, sseHistorySize),
	}
}

// AttachStore connects a durable EventStore to the hub. After attach,
// every Publish() also appends to the store. Optionally call
// HydrateFromStore() once to preload the in-memory ring with persisted
// events from a previous fusion run.
func (h *SSEHub) AttachStore(s *EventStore) {
	h.mu.Lock()
	h.store = s
	h.mu.Unlock()
}

// HydrateFromStore preloads the ring from `store` so a browser that
// reconnects right after fusion startup sees the same recent history
// it would have seen had fusion never restarted. Called once at
// startup, before any new events flow.
func (h *SSEHub) HydrateFromStore(store *EventStore) error {
	if store == nil {
		return nil
	}
	recent, err := store.Recent(sseHistorySize)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ev := range recent {
		h.history[h.histHead] = ev
		h.histHead = (h.histHead + 1) % sseHistorySize
		if h.histLen < sseHistorySize {
			h.histLen++
		}
	}
	return nil
}

// Publish sends `event` to every connected client and records it in the
// history ring. Non-blocking on broadcast: drops events for any client
// whose buffer is full. Caller retains ownership of `event`; we copy.
func (h *SSEHub) Publish(event []byte) {
	// Copy once outside the lock; everyone shares the same byte slice.
	cp := make([]byte, len(event))
	copy(cp, event)
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- cp:
		default:
			// Slow client. Drop this event for them; live ones are unaffected.
		}
	}
	// Record into the ring. Overwrite the oldest slot when full.
	h.history[h.histHead] = cp
	h.histHead = (h.histHead + 1) % sseHistorySize
	if h.histLen < sseHistorySize {
		h.histLen++
	}
	store := h.store
	h.mu.Unlock()
	// Mirror to disk outside the lock so a slow disk doesn't stall
	// live broadcast. Errors are logged once per occurrence via store
	// itself; here we silently continue so the publisher path is
	// uninterruptible.
	if store != nil {
		if err := store.Append(cp); err != nil {
			log.Printf("eventstore: append: %v", err)
		}
	}
}

// register adds a new SSE client and returns its inbound channel + an
// unregister fn that closes the channel and removes the client. The
// returned `replay` slice contains the history ring oldest-to-newest,
// to be sent before live events flow.
func (h *SSEHub) register() (chan []byte, [][]byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	// Snapshot history under the lock so a concurrent Publish can't race.
	replay := make([][]byte, 0, h.histLen)
	start := 0
	if h.histLen == sseHistorySize {
		start = h.histHead
	}
	for i := 0; i < h.histLen; i++ {
		idx := (start + i) % sseHistorySize
		if h.history[idx] != nil {
			replay = append(replay, h.history[idx])
		}
	}
	h.mu.Unlock()
	return ch, replay, func() {
		h.mu.Lock()
		delete(h.clients, ch)
		close(ch)
		h.mu.Unlock()
	}
}

// indexHTML is defined in dashboard.go as dashboardHTML.

// jsonError writes a JSON-encoded error response. Always uses
// encoding/json so dynamic strings (err.Error(), sensor names) can't
// produce malformed JSON when they contain quotes or backslashes.
func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonOK writes a 200 JSON object body. Same allocation discipline as
// jsonError -- uses encoding/json so values are escaped correctly.
func jsonOK(w http.ResponseWriter, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// authWrap returns a handler that requires the bearer token on every
// request. If `token` is empty, returns the inner handler unwrapped --
// no auth, matching the sniffer's `--api-token` semantics.
//
// Two ways to authenticate:
//   - Authorization: Bearer <token>  -- preferred, works for fetch()
//   - ?token=<token>                  -- needed for EventSource which
//                                        cannot set custom headers
//
// On failure: 401 with a JSON error. crypto/subtle constant-time compare
// so the check itself doesn't leak token length via timing.
func authWrap(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got string
		if h := r.Header.Get("Authorization"); h != "" {
			const p = "Bearer "
			if len(h) > len(p) && h[:len(p)] == p {
				got = h[len(p):]
			}
		}
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startWebServer runs an HTTP server on `listen` that serves the placeholder
// index, /events SSE endpoint, and /api/sensors registry endpoints.
// Returns when ctx is cancelled.
//
// `apiToken` (when non-empty) is required on /events and /api/* routes;
// the dashboard HTML at / is always served without auth so the operator
// can land on the page and the JS can pick up the token from a
// `?token=<T>` query param.
func startWebServer(ctx context.Context, listen string, hub *SSEHub, registry *Registry, store *EventStore, apiToken string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
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
	// Command fan-out endpoints: /api/fanout/keys, share-url, etc.
	installFanoutHandlers(apiMux, registry)
	// Clock-sync placement warnings. The dashboard health strip polls this
	// to render persistent "anchor X too close to station Y" banners that
	// would otherwise only surface in fusion's startup log. When clock-sync
	// is disabled, `enabled: false` lets the UI decide between "no banner"
	// vs "no anchors configured yet" messaging.
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

	// Evidence read endpoints. The Evidence tab loads "what happened
	// between start_ns and end_ns" from these by walking the time-keyed
	// buckets we already persisted. Read-only -- no replay execution
	// yet; that lands in a separate commit so this first slice can ship
	// independently of solver-mutation work.
	apiMux.HandleFunc("/api/evidence/clusters", evidenceClustersHandler(store))
	apiMux.HandleFunc("/api/evidence/pairs", evidencePairsHandler(store))
	apiMux.HandleFunc("/api/evidence/fixes", evidenceFixesHandler(store))
	apiMux.HandleFunc("/api/evidence/summary", evidenceSummaryHandler(store))

	// POST /api/resolve: event-time replay solver. Loads persisted
	// evidence + historical pair-offset snapshot and emits a
	// REPLAY_GEOLOCATED SSE event with the recomputed fix.
	apiMux.HandleFunc("/api/resolve", resolveHandler(store, hub))

	apiMux.HandleFunc("/api/dealer-stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dealer := registry.DealerHub()
		var stats []DealerStats
		if dealer != nil {
			stats = dealer.Stats()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sessions": stats})
	})
	apiMux.HandleFunc("/api/sensors/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /api/sensors/<name> (DELETE only).
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
	apiMux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// Same-origin only -- the dashboard HTML is served from the same
		// listener, so it doesn't need CORS. Dropping the wildcard means
		// a malicious page in the operator's browser can't EventSource
		// our live feed cross-origin.
		flusher.Flush()

		ch, replay, unregister := hub.register()
		defer unregister()

		// Replay buffered history first so browser refreshes reconstruct
		// state without waiting for new traffic.
		for _, ev := range replay {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", ev); err != nil {
				return
			}
		}
		flusher.Flush()

		// Periodic comment-line keepalive so transparent proxies don't
		// reap an idle connection.
		ka := time.NewTicker(20 * time.Second)
		defer ka.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			case <-ka.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", ev); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})

	// Mount the auth-gated handlers under /api/ and /events. authWrap is
	// a no-op when apiToken is empty so unauthenticated mode behaves as
	// before. The wrap is applied once at mount, not per-route, so
	// adding a new /api/* handler doesn't risk forgetting the wrap.
	wrapped := authWrap(apiMux, apiToken)
	mux.Handle("/api/", wrapped)
	mux.Handle("/events", wrapped)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("web: listening on http://%s/  (SSE: /events)", listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// parseEvidenceRange extracts start_ns / end_ns query params with
// sensible defaults: missing end_ns means "now"; missing start_ns means
// "one hour before end_ns". Returns (start, end, err) where err is
// non-nil only when a provided value fails to parse as uint64.
//
// One hour is the dashboard's default zoom; the API
// mirrors that so a request without params returns the same window the
// timeline starts on.
func parseEvidenceRange(r *http.Request) (uint64, uint64, error) {
	now := uint64(time.Now().UnixNano())
	endStr := r.URL.Query().Get("end_ns")
	end := now
	if endStr != "" {
		n, err := strconv.ParseUint(endStr, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("end_ns: %w", err)
		}
		end = n
	}
	startStr := r.URL.Query().Get("start_ns")
	var start uint64
	if startStr != "" {
		n, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("start_ns: %w", err)
		}
		start = n
	} else {
		const oneHourNs = uint64(time.Hour / time.Nanosecond)
		if end >= oneHourNs {
			start = end - oneHourNs
		}
	}
	if start > end {
		return 0, 0, fmt.Errorf("start_ns (%d) > end_ns (%d)", start, end)
	}
	return start, end, nil
}

// evidenceClustersHandler serves persisted cluster_observations for the
// Evidence tab timeline. Returns 200 + empty list when the store is nil
// (clock-sync-disabled-mode dashboard) so the UI logic is uniform.
func evidenceClustersHandler(store *EventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start, end, err := parseEvidenceRange(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		var records []ClusterObservationRecord
		if store != nil {
			records, err = store.ReadClusterObservationsRange(start, end)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if records == nil {
			records = []ClusterObservationRecord{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"start_ns":  start,
			"end_ns":    end,
			"persisted": store != nil,
			"count":     len(records),
			"records":   records,
		})
	}
}

// evidencePairsHandler serves pair_snapshots within the time range.
func evidencePairsHandler(store *EventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start, end, err := parseEvidenceRange(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		var records []PairSnapshotRecord
		if store != nil {
			records, err = store.ReadPairSnapshotsRange(start, end)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if records == nil {
			records = []PairSnapshotRecord{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"start_ns":  start,
			"end_ns":    end,
			"persisted": store != nil,
			"count":     len(records),
			"records":   records,
		})
	}
}

// evidenceFixesHandler serves cached solved_fixes within the time range.
func evidenceFixesHandler(store *EventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start, end, err := parseEvidenceRange(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		var records []SolvedFixRecord
		if store != nil {
			records, err = store.ReadSolvedFixesRange(start, end)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if records == nil {
			records = []SolvedFixRecord{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"start_ns":  start,
			"end_ns":    end,
			"persisted": store != nil,
			"count":     len(records),
			"records":   records,
		})
	}
}

// evidenceSummaryHandler exposes schema version, replay availability,
// and bucket row counts so the dashboard can render a one-line "DB has
// N clusters / N solves / replay v3" status. Used by the health strip
// at first paint and on tab focus.
func evidenceSummaryHandler(store *EventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var (
			schemaVer int
			replay    bool
			cnts      = map[string]int{
				"cluster_observations": 0,
				"pair_snapshots":       0,
				"solved_fixes":         0,
			}
		)
		if store != nil {
			schemaVer = store.SchemaVersion()
			replay = store.ReplayAvailable()
			if n, err := store.CountClusterObservations(); err == nil {
				cnts["cluster_observations"] = n
			}
			if n, err := store.CountPairSnapshots(); err == nil {
				cnts["pair_snapshots"] = n
			}
			if n, err := store.CountSolvedFixes(); err == nil {
				cnts["solved_fixes"] = n
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"persisted":        store != nil,
			"schema_version":   schemaVer,
			"replay_available": replay,
			"counts":           cnts,
		})
	}
}
