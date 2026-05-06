// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/c2_router.go: ROUTER socket that accepts inbound DEALER
// connections from sensors that opted into --c2-dealer. Tracks per-
// identity heartbeats and provides a request/reply path that the
// fanout layer prefers when an identity is currently online.
//
// Wire envelopes (matching c2_dealer.c on the sniffer side):
//   request:  {"cmd":"<name>","body":"<arg string>","id":<int>}
//   reply:    {"id":<int>,"status":<int>,"body":<json>}
//   heartbeat (sensor->fusion): {"event":"HEARTBEAT","station":"<name>","ts":<unix>}
//
// The hub never blocks the ROUTER read loop on user code; replies are
// matched via a per-request id and delivered through a buffered chan.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-zeromq/zmq4"
)

// dealerSession is the fusion-side view of one connected DEALER sensor.
type dealerSession struct {
	Identity string
	LastSeen time.Time
}

// DealerHub owns the ROUTER socket plus per-identity state. Safe for
// concurrent use; the read loop runs on its own goroutine.
type DealerHub struct {
	mu       sync.Mutex
	sessions map[string]*dealerSession
	pending  map[int64]chan dealerReply // id -> reply channel

	sck      zmq4.Socket
	nextID   atomic.Int64
	hub      *SSEHub                    // optional: for forwarding heartbeats to dashboard
}

type dealerReply struct {
	Status int
	Body   json.RawMessage
}

// NewDealerHub binds a ROUTER socket on `endpoint` (e.g. "tcp://*:7009")
// and starts the read loop. Returns a hub with a nil socket if endpoint
// is empty or binding fails -- callers should treat that as "DEALER
// transport disabled" rather than fatal.
func NewDealerHub(ctx context.Context, endpoint string, hub *SSEHub) *DealerHub {
	d := &DealerHub{
		sessions: map[string]*dealerSession{},
		pending:  map[int64]chan dealerReply{},
		hub:      hub,
	}
	if endpoint == "" {
		return d
	}
	sck := zmq4.NewRouter(ctx)
	if err := sck.Listen(endpoint); err != nil {
		log.Printf("c2-router: listen %s: %v", endpoint, err)
		return d
	}
	d.sck = sck
	go d.readLoop(ctx)
	log.Printf("c2-router: listening on %s for sensor DEALER connections", endpoint)
	return d
}

// Sessions returns a snapshot of currently-known DEALER sessions.
// Caller must not mutate; safe to read.
func (d *DealerHub) Sessions() []dealerSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]dealerSession, 0, len(d.sessions))
	for _, s := range d.sessions {
		out = append(out, *s)
	}
	return out
}

// HasSession reports whether a sensor with that identity is currently
// connected via DEALER, with the last heartbeat under 90s old.
func (d *DealerHub) HasSession(identity string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[identity]
	if !ok {
		return false
	}
	return time.Since(s.LastSeen) < 90*time.Second
}

// SendCommand sends a command envelope to the named DEALER identity
// and waits up to `timeout` for a reply. Returns the reply status (HTTP
// style) and body. ErrNoSession means the identity is not currently
// connected; ErrTimeout means the sensor accepted but didn't reply.
func (d *DealerHub) SendCommand(identity, cmd, body string, timeout time.Duration) (int, string, error) {
	if d.sck == nil {
		return 0, "", errors.New("dealer transport disabled")
	}
	if !d.HasSession(identity) {
		return 0, "", ErrNoSession
	}
	id := d.nextID.Add(1)
	ch := make(chan dealerReply, 1)
	d.mu.Lock()
	d.pending[id] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
	}()

	envelope, err := json.Marshal(struct {
		Cmd  string `json:"cmd"`
		Body string `json:"body,omitempty"`
		ID   int64  `json:"id"`
	}{Cmd: cmd, Body: body, ID: id})
	if err != nil {
		return 0, "", err
	}

	msg := zmq4.NewMsgFrom([]byte(identity), envelope)
	if err := d.sck.SendMulti(msg); err != nil {
		return 0, "", fmt.Errorf("dealer send: %w", err)
	}
	select {
	case r := <-ch:
		return r.Status, string(r.Body), nil
	case <-time.After(timeout):
		return 0, "", ErrTimeout
	}
}

var (
	ErrNoSession = errors.New("sensor not connected via DEALER")
	ErrTimeout   = errors.New("DEALER reply timeout")
)

// readLoop pulls messages from the ROUTER socket. msg.Frames[0] is the
// sender identity (zmq routes it to us); msg.Frames[1] is the JSON
// envelope. We classify frame contents by the "event" field for
// heartbeats vs the "id" field for command replies.
func (d *DealerHub) readLoop(ctx context.Context) {
	for {
		msg, err := d.sck.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("c2-router: recv: %v", err)
			continue
		}
		if len(msg.Frames) < 2 {
			continue
		}
		identity := string(msg.Frames[0])
		payload := msg.Frames[1]

		// Classify: heartbeat events vs command replies. A reply has
		// {"id":N,"status":...,"body":...}; a heartbeat has "event".
		var probe struct {
			Event  string          `json:"event,omitempty"`
			ID     *int64          `json:"id,omitempty"`
			Status int             `json:"status,omitempty"`
			Body   json.RawMessage `json:"body,omitempty"`
		}
		if err := json.Unmarshal(payload, &probe); err != nil {
			continue
		}

		// Update session record on every received frame, regardless of
		// kind -- any traffic counts as alive.
		d.touchSession(identity)

		if probe.Event != "" {
			// Heartbeat / status frame. Forward through the SSE hub so
			// the dashboard's Sensors tab can react in real time. We
			// inject the identity as the "station" tag if missing.
			if d.hub != nil {
				out := payload
				if !containsKey(payload, "station") {
					tagged, err := injectStation(payload, identity)
					if err == nil {
						out = tagged
					}
				}
				d.hub.Publish(out)
			}
			continue
		}

		if probe.ID != nil {
			d.mu.Lock()
			ch, ok := d.pending[*probe.ID]
			d.mu.Unlock()
			if ok {
				select {
				case ch <- dealerReply{Status: probe.Status, Body: probe.Body}:
				default:
				}
			}
		}
	}
}

func (d *DealerHub) touchSession(identity string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[identity]
	if !ok {
		s = &dealerSession{Identity: identity}
		d.sessions[identity] = s
		log.Printf("c2-router: DEALER session opened: %s", identity)
	}
	s.LastSeen = time.Now()
}

// containsKey is a fast-path check that doesn't allocate; sufficient for
// the shapes our heartbeat envelopes use.
func containsKey(b []byte, key string) bool {
	needle := `"` + key + `":`
	return len(b) >= len(needle) && stringContains(string(b), needle)
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func injectStation(payload []byte, identity string) ([]byte, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(payload, &generic); err != nil {
		return nil, err
	}
	if _, has := generic["station"]; !has {
		raw, _ := json.Marshal(identity)
		generic["station"] = raw
	}
	return json.Marshal(generic)
}
