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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
}

func newSSEHub() *SSEHub {
	return &SSEHub{
		clients: map[chan []byte]struct{}{},
		history: make([][]byte, sseHistorySize),
	}
}

// Publish sends `event` to every connected client and records it in the
// history ring. Non-blocking on broadcast: drops events for any client
// whose buffer is full. Caller retains ownership of `event`; we copy.
func (h *SSEHub) Publish(event []byte) {
	// Copy once outside the lock; everyone shares the same byte slice.
	cp := make([]byte, len(event))
	copy(cp, event)
	h.mu.Lock()
	defer h.mu.Unlock()
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

// startWebServer runs an HTTP server on `listen` that serves the placeholder
// index, /events SSE endpoint, and /api/sensors registry endpoints.
// Returns when ctx is cancelled.
func startWebServer(ctx context.Context, listen string, hub *SSEHub, registry *Registry) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/sensors", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(registry.List())
		case http.MethodPost:
			var s Sensor
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
				return
			}
			if err := registry.Add(&s); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"added":"%s"}`, s.Name)
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
	// Command fan-out endpoints: /api/fanout/keys, share-url, etc.
	installFanoutHandlers(mux, registry)
	mux.HandleFunc("/api/sensors/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /api/sensors/<name> (DELETE only).
		if r.Method != http.MethodDelete {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path[len("/api/sensors/"):]
		if name == "" {
			http.Error(w, `{"error":"missing name"}`, http.StatusBadRequest)
			return
		}
		if err := registry.Remove(name); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"removed":"%s"}`, name)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
