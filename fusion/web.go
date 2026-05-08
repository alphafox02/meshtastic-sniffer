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
type SSEHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newSSEHub() *SSEHub {
	return &SSEHub{clients: map[chan []byte]struct{}{}}
}

// Publish sends `event` (raw JSON, no SSE framing) to every connected
// client. Non-blocking: drops events for any client whose buffer is full.
func (h *SSEHub) Publish(event []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
			// Slow client. Drop this event for them; live ones are unaffected.
		}
	}
}

// register adds a new SSE client and returns its inbound channel + an
// unregister fn that closes the channel and removes the client.
func (h *SSEHub) register() (chan []byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.clients, ch)
		close(ch)
		h.mu.Unlock()
	}
}

const indexHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>meshtastic-fusion</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
     max-width:780px;margin:40px auto;padding:0 20px;line-height:1.5}
h1{color:#38bdf8;margin-bottom:6px;font-weight:600}
.muted{color:#64748b}
code{background:#1e293b;padding:2px 6px;border-radius:3px;color:#bae6fd}
</style></head><body>
<h1>meshtastic-fusion</h1>
<p class=muted>Multi-station aggregator. Web dashboard arrives in a follow-up commit.</p>
<p>Live event stream: <code>GET /events</code> (Server-Sent Events).</p>
<p>Each event is a JSON line tagged with the originating station (the sniffer's
<code>--station-id</code>). Same wire shape as the per-sniffer dashboard's SSE.</p>
</body></html>`

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
		_, _ = w.Write([]byte(indexHTML))
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

		ch, unregister := hub.register()
		defer unregister()

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
