// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/sensors.go: persistent sensor registry + dynamic subscriber pool.
//
// The Registry holds a list of Sensor entries (name, zmq endpoint, api
// endpoint, optional auth token, optional CurveZMQ pubkey) and can
// load/save itself from JSON. The Pool wraps the ZMQ-subscriber
// goroutines so the registry can add/remove subscribers at runtime via
// /api/sensors POST and DELETE handlers.
//
// Persistence is intentionally simple: a single JSON file written
// atomically (write-temp + rename) on each mutation. Hundreds of
// sensors fit fine; SQLite would be overkill at this scale.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-zeromq/zmq4"
)

// Sensor is one station entry: identity + how to reach its telemetry
// (ZMQ) and command (HTTP) endpoints. ApiToken and CurvePub are
// optional; absence means "no auth" / "no CurveZMQ on the wire".
type Sensor struct {
	Name      string  `json:"name"`
	Zmq       string  `json:"zmq"`             // e.g. "tcp://10.0.0.5:7008"
	Api       string  `json:"api,omitempty"`   // e.g. "http://10.0.0.5:8888"
	ApiToken  string  `json:"api_token,omitempty"`
	CurvePub  string  `json:"curve_pub,omitempty"`
	Lat       float64 `json:"lat,omitempty"`
	Lon       float64 `json:"lon,omitempty"`
	AltM      float64 `json:"alt_m,omitempty"`
	// LastSeen tracks the most recent event timestamp from this sensor's
	// stream; updated by the subscriber loop. Not persisted.
	LastSeen time.Time `json:"-"`
	// Dealer is true when the fusion is currently receiving heartbeats
	// from this sensor over its ROUTER socket. Dashboard surfaces a
	// badge in the Sensors tab so operators can tell which transport
	// fan-out commands will travel over.
	Dealer bool `json:"dealer,omitempty"`
}

// Registry is the in-memory list + the disk-backed file. All public
// methods take the mutex; the file is rewritten on every mutation.
type Registry struct {
	mu       sync.Mutex
	path     string             // empty = no persistence
	byName   map[string]*Sensor // name -> entry
	pool     *SubscriberPool    // dynamic subscriber manager
	hub      *SSEHub            // for forwarding raw events
	dealer   *DealerHub         // optional: nil when --c2-router not set
}

// SetDealerHub wires in the DEALER C2 hub so the fanout layer can
// prefer DEALER over HTTP when a sensor is connected via DEALER.
// Optional; nil = HTTP-only fan-out.
func (r *Registry) SetDealerHub(d *DealerHub) {
	r.mu.Lock()
	r.dealer = d
	r.mu.Unlock()
}

func (r *Registry) DealerHub() *DealerHub {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dealer
}

// NewRegistry creates a registry, optionally loading from `path`. The
// file is created if absent on the first mutation; missing-file at load
// is not an error. Pool and hub are forwarded to subscribe goroutines
// so newly-added sensors start streaming immediately.
func NewRegistry(ctx context.Context, path string, hub *SSEHub) (*Registry, error) {
	r := &Registry{
		path:   path,
		byName: map[string]*Sensor{},
		hub:    hub,
	}
	r.pool = NewSubscriberPool(ctx, hub)
	if path != "" {
		if err := r.load(); err != nil {
			return nil, fmt.Errorf("registry load %s: %w", path, err)
		}
	}
	// Start subscribers for everything loaded from disk.
	for _, s := range r.byName {
		r.pool.Add(s.Name, s.Zmq)
	}
	return r, nil
}

func (r *Registry) load() error {
	b, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []Sensor
	if err := json.Unmarshal(b, &entries); err != nil {
		return err
	}
	for i := range entries {
		s := entries[i]
		r.byName[s.Name] = &s
	}
	log.Printf("registry: loaded %d sensors from %s", len(entries), r.path)
	return nil
}

// saveLocked writes the current registry to disk under r.path. Must be
// called with r.mu held. No-op when path is empty (memory-only mode).
func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*Sensor, 0, len(r.byName))
	for _, s := range r.byName {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// Add inserts or updates a sensor by name. Returns whether the
// underlying subscriber pool action was a fresh add vs replacement.
func (r *Registry) Add(s *Sensor) error {
	if s == nil || s.Name == "" || s.Zmq == "" {
		return errors.New("sensor must have non-empty name and zmq endpoint")
	}
	r.mu.Lock()
	prev, existed := r.byName[s.Name]
	r.byName[s.Name] = s
	if err := r.saveLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()
	if existed && prev.Zmq == s.Zmq {
		return nil // identity / token / api updated; subscriber unaffected
	}
	if existed {
		r.pool.Remove(s.Name)
	}
	r.pool.Add(s.Name, s.Zmq)
	return nil
}

func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	if _, ok := r.byName[name]; !ok {
		r.mu.Unlock()
		return errors.New("no such sensor")
	}
	delete(r.byName, name)
	if err := r.saveLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()
	r.pool.Remove(name)
	return nil
}

// List returns a copy of the current registry, sorted by name. Each
// returned Sensor has its Dealer field populated from the live hub.
func (r *Registry) List() []Sensor {
	r.mu.Lock()
	dealer := r.dealer
	out := make([]Sensor, 0, len(r.byName))
	for _, s := range r.byName {
		out = append(out, *s)
	}
	r.mu.Unlock()
	for i := range out {
		if dealer != nil {
			out[i].Dealer = dealer.HasSession(out[i].Name)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SubscriberPool manages one ZMQ SUB goroutine per (name, endpoint)
// pair. Add/Remove are concurrent-safe; goroutines run until their
// per-entry context is cancelled. Each received message is published
// to the hub (for SSE clients) and forwarded to `raw` (for the dedup
// cluster loop).
type SubscriberPool struct {
	ctx     context.Context // parent: cancelled at shutdown
	hub     *SSEHub
	raw     chan<- []byte
	mu      sync.Mutex
	cancels map[string]context.CancelFunc // name -> cancel
}

func NewSubscriberPool(ctx context.Context, hub *SSEHub) *SubscriberPool {
	return &SubscriberPool{
		ctx:     ctx,
		hub:     hub,
		cancels: map[string]context.CancelFunc{},
	}
}

// SetRawChannel wires a chan that receives every parsed message body.
// main() calls this before any Add() so the dedup loop sees events
// from registry-driven sensors as well as CLI-arg sensors.
func (p *SubscriberPool) SetRawChannel(raw chan<- []byte) {
	p.mu.Lock()
	p.raw = raw
	p.mu.Unlock()
}

// Add starts (or replaces) the subscriber for `name`. Returns
// immediately; the goroutine handles connect + recv loop in the
// background. A previous subscriber under the same name is cancelled.
func (p *SubscriberPool) Add(name, endpoint string) {
	p.mu.Lock()
	if cancel, ok := p.cancels[name]; ok {
		cancel()
	}
	subCtx, cancel := context.WithCancel(p.ctx)
	p.cancels[name] = cancel
	raw := p.raw
	hub := p.hub
	p.mu.Unlock()

	go func() {
		s := zmq4.NewSub(subCtx)
		defer s.Close()
		s.SetOption(zmq4.OptionSubscribe, "")
		if err := s.Dial(endpoint); err != nil {
			log.Printf("subscriber[%s] dial %s: %v", name, endpoint, err)
			return
		}
		log.Printf("subscriber[%s] connected to %s", name, endpoint)
		for {
			msg, err := s.Recv()
			if err != nil {
				if subCtx.Err() != nil {
					log.Printf("subscriber[%s] stopped", name)
					return
				}
				log.Printf("subscriber[%s] recv: %v", name, err)
				return
			}
			if len(msg.Frames) == 0 {
				continue
			}
			payload := msg.Frames[0]
			/* Defensive station tagging: if the sniffer-side event JSON
			 * doesn't already carry "station":"..." (older builds, or
			 * STATS heartbeat events from a sniffer without
			 * --station-id), inject the registry name. The dashboard
			 * needs a station label per event for multi-sensor accounting. */
			if !bytes.Contains(payload, []byte(`"station":`)) && len(payload) > 1 && payload[0] == '{' {
				inj := []byte(fmt.Sprintf(`{"station":%q,`, name))
				payload = append(inj, payload[1:]...)
			}
			if hub != nil {
				hub.Publish(payload)
			}
			if raw != nil {
				select {
				case raw <- payload:
				case <-subCtx.Done():
					return
				}
			}
		}
	}()
}

func (p *SubscriberPool) Remove(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cancel, ok := p.cancels[name]; ok {
		cancel()
		delete(p.cancels, name)
	}
}

// EndpointCount returns how many subscribers are currently active.
func (p *SubscriberPool) EndpointCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.cancels)
}
