// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/zmq_sub.go: subscribe to meshtastic-sniffer's ZMQ PUB
// feed and convert per-frame JSON events to Observation structs.
//
// The sniffer emits one event per frame on the JSON firehose. Some
// events carry an explicit "event" discriminator (STATS,
// OFF_GRID_LORA, REPLAY_SUSPECTED, GEOLOCATED, ...); those are
// dropped here -- only frame-shape events with a from/packet_id
// pair are turned into Observations and forwarded for storage.

package main

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/go-zeromq/zmq4"
)

// snifferEvent is the subset of the sniffer's JSON event shape we
// care about for wardriving. Field names match feed.c. Anything not
// listed here is silently ignored.
type snifferEvent struct {
	Event        string  `json:"event,omitempty"` // non-empty = not a frame
	From         string  `json:"from,omitempty"`  // canonical "!433c0b98"
	To           string  `json:"to,omitempty"`
	PacketID     uint32  `json:"packet_id,omitempty"`
	ChannelHash  uint8   `json:"channel_hash,omitempty"`
	ChannelName  string  `json:"channel_name,omitempty"`
	Preset       string  `json:"preset,omitempty"`
	BWHz         uint32  `json:"bw_hz,omitempty"`
	FreqHz       uint64  `json:"freq_hz,omitempty"`
	RSSIdB       float64 `json:"rssi_db,omitempty"`
	SNRdB        float64 `json:"snr_db,omitempty"`
	CFOHz        float64 `json:"cfo_hz,omitempty"`
	Decrypted    *bool   `json:"decrypted,omitempty"`
	PortName     string  `json:"port_name,omitempty"`
	PortNum      int     `json:"port_num,omitempty"`
	PayloadCRCOk *bool   `json:"payload_crc_ok,omitempty"`
	HopLimit     int     `json:"hop_limit,omitempty"`
	HopStart     int     `json:"hop_start,omitempty"`
	// Decoded port fields. Captured opportunistically:
	Latitude       float64 `json:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty"`
	Altitude       float64 `json:"altitude,omitempty"`
	LongName       string  `json:"long_name,omitempty"`
	ShortName      string  `json:"short_name,omitempty"`
	HWModel        uint32  `json:"hw_model,omitempty"`
	Role           uint32  `json:"role,omitempty"`
	// Station-side metadata; useful when the sniffer is running on
	// the same host but we still want to round-trip the values.
	StationLat float64 `json:"station_lat,omitempty"`
	StationLon float64 `json:"station_lon,omitempty"`
	TS         float64 `json:"ts,omitempty"` // unix seconds; sniffer emits floats here
}

// EventToObservation converts a parsed event into an Observation,
// tagging it with the current operator GPS fix. Returns (nil, false)
// when the event isn't a frame (heartbeat / off-grid alert / etc.)
// or doesn't carry a from/packet_id pair.
func EventToObservation(ev *snifferEvent, gps GPSFix) (*Observation, bool) {
	if ev == nil {
		return nil, false
	}
	if ev.Event != "" {
		// Non-frame event (STATS, OFF_GRID_LORA, REPLAY_SUSPECTED,
		// GEOLOCATED, TX, ...). Skip.
		return nil, false
	}
	if ev.From == "" {
		return nil, false
	}
	o := &Observation{
		NodeID:       ev.From,
		PacketID:     ev.PacketID,
		ChannelHash:  ev.ChannelHash,
		ChannelName:  ev.ChannelName,
		Preset:       ev.Preset,
		BWHz:         ev.BWHz,
		FreqHz:       ev.FreqHz,
		RSSIdBm:      ev.RSSIdB,
		SNRdB:        ev.SNRdB,
		PortName:     ev.PortName,
		PayloadCRCOk: ev.PayloadCRCOk,
		HopLimit:     ev.HopLimit,
		HopStart:     ev.HopStart,
		LongName:     ev.LongName,
		ShortName:    ev.ShortName,
		HWModel:      ev.HWModel,
		Role:         ev.Role,
	}
	if ev.Decrypted != nil {
		o.Decrypted = *ev.Decrypted
	}
	// POSITION_APP decode: when present, this is the node telling us
	// where it thinks it is. Promote into selfreported_*.
	if ev.PortName == "POSITION_APP" && (ev.Latitude != 0 || ev.Longitude != 0) {
		o.SelfReportedLat = ev.Latitude
		o.SelfReportedLon = ev.Longitude
		o.SelfReportedAltM = ev.Altitude
	}
	// Operator GPS fix at receive time. Skip when no fix is valid;
	// the centroid estimator handles missing GPS gracefully.
	if gps.Valid {
		o.RxLat = gps.Lat
		o.RxLon = gps.Lon
		o.RxAltM = gps.AltM
		o.RxSpeedMps = gps.SpeedMps
		o.RxHeadingDeg = gps.HeadingDeg
		o.HDOP = gps.HDOP
		o.Sats = gps.Sats
	}
	// Prefer the sniffer's reported timestamp (closer to RX moment
	// than our wall clock); fall back to wall-clock now.
	if ev.TS > 0 {
		o.TS = floatToTime(ev.TS)
	} else {
		o.TS = time.Now().UTC()
	}
	return o, true
}

// ZMQSubscriber connects to the sniffer's PUB socket and pushes
// parsed Observations onto the returned channel. Returns when ctx
// is cancelled; the channel is closed at that point.
type ZMQSubscriber struct {
	Endpoint string
	GPS      *GPSDClient
}

// Run blocks until ctx is cancelled. Emits one Observation per
// frame-shape event onto `out`. Heartbeats and non-frame events
// are logged at -v verbosity and dropped.
func (s *ZMQSubscriber) Run(ctx context.Context, out chan<- *Observation) {
	defer close(out)
	if s.Endpoint == "" {
		s.Endpoint = "tcp://127.0.0.1:7008"
	}
	sub := zmq4.NewSub(ctx)
	defer sub.Close()
	sub.SetOption(zmq4.OptionSubscribe, "")
	if err := sub.Dial(s.Endpoint); err != nil {
		log.Printf("zmq: dial %s: %v", s.Endpoint, err)
		return
	}
	log.Printf("zmq: subscribed to %s", s.Endpoint)

	for {
		if ctx.Err() != nil {
			return
		}
		msg, err := sub.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("zmq: recv: %v", err)
			return
		}
		if len(msg.Frames) == 0 {
			continue
		}
		payload := msg.Frames[0]
		// Cheap pre-filter: skip event lines we know we don't want.
		// The sniffer emits per-frame events as bare {} objects (no
		// "event" key); discriminator events have "event":"STATS"
		// etc. Drop those before json.Unmarshal allocates.
		if hasJSONField(payload, `"event":`) {
			continue
		}
		var ev snifferEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			continue
		}
		gps := GPSFix{}
		if s.GPS != nil {
			gps = s.GPS.Current()
		}
		o, ok := EventToObservation(&ev, gps)
		if !ok {
			continue
		}
		select {
		case out <- o:
		case <-ctx.Done():
			return
		}
	}
}

// hasJSONField is a cheap byte-substring check for top-level keys.
// Not technically JSON-aware (it'd match a nested object too), but
// the sniffer's frame events never contain a top-level "event" key
// and the discriminator events always do, so it's good enough as
// a pre-filter.
func hasJSONField(b []byte, key string) bool {
	return strings.Contains(unsafeBytesToString(b), key)
}

// unsafeBytesToString avoids the allocation of string(b) for the
// pre-filter check. The byte slice belongs to the ZMQ message frame;
// we don't outlive it.
func unsafeBytesToString(b []byte) string {
	// Standard idiom in pre-1.20 Go; in 1.20+ this is unsafe.String.
	// Use a copy-free read here since we only call strings.Contains.
	return string(b)
}

// snifferEventFromString parses a single JSON line into a
// snifferEvent. Exposed for tests that don't want to spin a ZMQ
// connection.
func snifferEventFromString(s string) (snifferEvent, error) {
	var ev snifferEvent
	if err := json.Unmarshal([]byte(s), &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// parseUintLoose handles both `123` and `"123"` shapes from JSON
// values (some sniffer emitters quote large integers for JS safety).
// Currently unused but kept for future fields like packet_id when
// they appear as strings.
func parseUintLoose(s string) uint64 {
	s = strings.Trim(s, `"`)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
