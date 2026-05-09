// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// meshtastic-fusion: central aggregator for one-or-more meshtastic-sniffer
// stations. Subscribes to N sniffer ZMQ PUB feeds, groups same-packet
// observations across stations by (from, packet_id) within a time window,
// and prints / serves a consolidated view.
//
// Sniffer-side (each station) emits JSON events tagged with `station`,
// `station_lat`, `station_lon`, `station_alt_m` (when --gpsd is running)
// over ZMQ PUB. Fusion connects to N of those endpoints and presents the
// "where each station heard each packet" picture in one place.
//
// This file is the v0 CLI subscriber. Web dashboard, sensor management
// API, and C2 fan-out land in subsequent commits behind their own flags
// so the binary stays usable at every step.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Frame is the subset of sniffer event JSON fields we care about for
// multi-station correlation. Anything else passes through unparsed.
type Frame struct {
	Event          string  `json:"event,omitempty"`
	Station        string  `json:"station,omitempty"`
	StationLat     float64 `json:"station_lat,omitempty"`
	StationLon     float64 `json:"station_lon,omitempty"`
	StationAltM    float64 `json:"station_alt_m,omitempty"`
	StationTNs     uint64  `json:"station_t_ns,omitempty"`     /* sensor capture timestamp (ns since epoch) */
	StationTAccNs  uint32  `json:"station_t_acc_ns,omitempty"` /* clock-discipline class for mlat weighting */
	From           string  `json:"from,omitempty"`
	PacketID       uint32  `json:"packet_id,omitempty"`
	ChannelHash    uint8   `json:"channel_hash,omitempty"`     /* 1-byte routing hash from radio header */
	SlotID         int     `json:"slot_id,omitempty"`          /* decoder slot index that caught the frame */
	ChannelName    string  `json:"channel_name,omitempty"`     /* human label, only when decrypted */
	Preset         string  `json:"preset,omitempty"`
	HopLimit       int     `json:"hop_limit,omitempty"`
	HopStart       int     `json:"hop_start,omitempty"`
	SnrDB          float64 `json:"snr_db,omitempty"`
	RssiDB         float64 `json:"rssi_db,omitempty"`
	Decrypted      *bool   `json:"decrypted,omitempty"`
	PortName       string  `json:"port_name,omitempty"`
}

// Observation is one (station, frame) tuple inside a cluster.
type Observation struct {
	Station       string
	StationLat    float64
	StationLon    float64
	StationAltM   float64
	StationTNs    uint64
	StationTAccNs uint32
	SnrDB         float64
	RssiDB        float64
	At            time.Time
}

// Cluster groups same-packet observations from one transmission.
type Cluster struct {
	Key          string // "from|packet_id"
	FirstSeen    time.Time
	Frame        Frame // representative (first-seen) frame for non-station fields
	Observations []Observation
}

func clusterKey(from string, pid uint32) string {
	return fmt.Sprintf("%s|%d", from, pid)
}

// Subscriber management is in sensors.go's SubscriberPool. CLI-arg
// endpoints are added to the pool with synthetic names like
// "cli-tcp://host:port" so they coexist with registry-driven sensors
// using the same add/remove mechanism.

// flushReady removes clusters older than `window` from `pending`,
// returning them sorted by first-seen.
func flushReady(pending map[string]*Cluster, window time.Duration, now time.Time) []*Cluster {
	var ready []*Cluster
	for k, c := range pending {
		if now.Sub(c.FirstSeen) > window {
			ready = append(ready, c)
			delete(pending, k)
		}
	}
	sort.Slice(ready, func(i, j int) bool {
		return ready[i].FirstSeen.Before(ready[j].FirstSeen)
	})
	return ready
}

func printCluster(c *Cluster, totalStations int) {
	stations := map[string]bool{}
	parts := make([]string, 0, len(c.Observations))
	for _, o := range c.Observations {
		stations[o.Station] = true
		if o.SnrDB != 0 {
			parts = append(parts, fmt.Sprintf("%s=%.1fdB", o.Station, o.SnrDB))
		} else {
			parts = append(parts, o.Station)
		}
	}
	chName := c.Frame.ChannelName
	if chName == "" {
		chName = "(encrypted)"
	}
	preset := c.Frame.Preset
	if preset == "" {
		preset = "?"
	}
	fmt.Printf("%-11s pid=%-10d %-11s ch=%-12s hop=%d/%d  heard-by=%d/%d [%s]\n",
		c.Frame.From, c.Frame.PacketID, preset, chName,
		c.Frame.HopLimit, c.Frame.HopStart,
		len(stations), totalStations, strings.Join(parts, ", "))
}

// txEventJSON returns the consolidated cluster as a JSON line for SSE
// publication. Distinct event type ('TX') so dashboard JS can keyhole
// it from the raw per-frame events that flow alongside.
func txEventJSON(c *Cluster, totalStations int) ([]byte, error) {
	type stationObs struct {
		Name   string  `json:"name"`
		SnrDB  float64 `json:"snr_db,omitempty"`
		Lat    float64 `json:"lat,omitempty"`
		Lon    float64 `json:"lon,omitempty"`
	}
	out := struct {
		Event       string       `json:"event"`
		From        string       `json:"from"`
		PacketID    uint32       `json:"packet_id"`
		ChannelName string       `json:"channel_name,omitempty"`
		Preset      string       `json:"preset,omitempty"`
		HopLimit    int          `json:"hop_limit"`
		HopStart    int          `json:"hop_start"`
		Stations    []stationObs `json:"stations"`
		TotalSensors int         `json:"total_sensors"`
	}{
		Event: "TX", From: c.Frame.From, PacketID: c.Frame.PacketID,
		ChannelName: c.Frame.ChannelName, Preset: c.Frame.Preset,
		HopLimit: c.Frame.HopLimit, HopStart: c.Frame.HopStart,
		TotalSensors: totalStations,
	}
	for _, o := range c.Observations {
		out.Stations = append(out.Stations, stationObs{
			Name: o.Station, SnrDB: o.SnrDB, Lat: o.StationLat, Lon: o.StationLon,
		})
	}
	return json.Marshal(out)
}

func main() {
	window := flag.Duration("window", 5*time.Second,
		"Dedup window across stations (e.g. 3s, 250ms)")
	maxFrames := flag.Int("max-frames", 0,
		"Stop after N consolidated frames (0 = unlimited)")
	listen := flag.String("listen", "",
		"HTTP listen address (e.g. :9000). Empty = CLI-only mode.")
	sensorsFile := flag.String("sensors-file", "",
		"Path to persistent sensor registry JSON. Empty = CLI-args only.")
	c2Router := flag.String("c2-router", "",
		"ZMQ ROUTER bind address (e.g. tcp://*:7009) for DEALER C2 from sensors. Empty = HTTP fan-out only.")
	apiToken := flag.String("api-token", "",
		"Bearer token required for /events and /api/* (Authorization: Bearer <T>, or ?token=<T> on EventSource). Empty = no auth.")
	stateDB := flag.String("state-db", "",
		"Path to bbolt file for SSE replay-ring persistence (e.g. ~/.config/meshtastic-fusion/state.db). Empty = memory-only; ring is lost on restart.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [flags] tcp://host1:7008 tcp://host2:7008 ...\n\n"+
				"Subscribes to N meshtastic-sniffer ZMQ PUB feeds, groups same-packet\n"+
				"observations by (from, packet_id), prints one consolidated line per\n"+
				"real transmission with which stations heard it.\n\nFlags:\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	endpoints := flag.Args()
	// Accept zero sensors at startup if either a sensors-file is
	// configured (sensors get added at runtime via /api/sensors POST or
	// auto-announce) or a c2-router is up (sensors will dial in via
	// DEALER and self-register through the announce path).
	if len(endpoints) == 0 && *sensorsFile == "" && *c2Router == "" && *listen == "" {
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Printf("shutting down...")
		cancel()
	}()

	var hub *SSEHub
	var store *EventStore
	if *listen != "" {
		hub = newSSEHub()
		if *stateDB != "" {
			s, err := OpenEventStore(*stateDB, 0)
			if err != nil {
				log.Fatalf("state-db: %v", err)
			}
			store = s
			defer store.Close()
			if err := hub.HydrateFromStore(store); err != nil {
				log.Printf("state-db: hydrate: %v", err)
			}
			n, _ := store.Count()
			log.Printf("state-db: %s opened, %d events on disk", *stateDB, n)
			hub.AttachStore(store)
		}
	}

	// Sensor registry + subscriber pool. Pool starts subscribers on
	// behalf of both CLI-arg endpoints and registry entries; runtime
	// add/remove via /api/sensors mutates registry which mutates pool.
	registry, err := NewRegistry(ctx, *sensorsFile, hub)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	raw := make(chan []byte, 256)
	registry.pool.SetRawChannel(raw)
	for _, ep := range endpoints {
		registry.pool.Add("cli-"+ep, ep)
	}

	dealerHub := NewDealerHub(ctx, *c2Router, hub)
	registry.SetDealerHub(dealerHub)

	if *listen != "" {
		go func() {
			if err := startWebServer(ctx, *listen, hub, registry, *apiToken); err != nil {
				log.Printf("web: %v", err)
				cancel()
			}
		}()
	}

	pending := map[string]*Cluster{}
	consolidated := 0
	tick := time.NewTicker(*window / 4)
	defer tick.Stop()

loop:
	for {
		select {
		case b, ok := <-raw:
			if !ok {
				break loop
			}
			var f Frame
			if err := json.Unmarshal(b, &f); err != nil {
				continue
			}
			if f.Event != "" {
				// STATS / OFF_GRID_LORA / REPLAY_SUSPECTED -- not packet data.
				// In a future commit we'll surface these too.
				continue
			}
			if f.From == "" || f.PacketID == 0 {
				continue
			}
			key := clusterKey(f.From, f.PacketID)
			c, ok := pending[key]
			now := time.Now()
			if !ok {
				c = &Cluster{Key: key, FirstSeen: now, Frame: f}
				pending[key] = c
			}
			station := f.Station
			if station == "" {
				station = "(unnamed)"
			}
			c.Observations = append(c.Observations, Observation{
				Station: station, StationLat: f.StationLat, StationLon: f.StationLon,
				StationAltM: f.StationAltM, StationTNs: f.StationTNs, StationTAccNs: f.StationTAccNs,
				SnrDB: f.SnrDB, RssiDB: f.RssiDB, At: now,
			})
		case now := <-tick.C:
			ready := flushReady(pending, *window, now)
			for _, c := range ready {
				printCluster(c, registry.pool.EndpointCount())
				if hub != nil {
					if b, err := txEventJSON(c, registry.pool.EndpointCount()); err == nil {
						hub.Publish(b)
					}
					/* Multilateration: when 3+ observations carry station
					 * positions and timestamps, run the solver and publish
					 * a GEOLOCATED event alongside the TX consolidation. */
					if g := tryGeolocate(c); g != nil {
						hub.Publish(g)
					}
				}
				consolidated++
				if *maxFrames > 0 && consolidated >= *maxFrames {
					cancel()
					return
				}
			}
		case <-ctx.Done():
			break loop
		}
	}

	// Final flush of anything still pending past the window.
	for _, c := range flushReady(pending, 0, time.Now()) {
		printCluster(c, registry.pool.EndpointCount())
	}
}

// tryGeolocate runs the mlat solver on a cluster's observations.
// Filters out observations without a station position or timestamp,
// runs Solve when 3+ usable observations remain, and returns a
// JSON-encoded GEOLOCATED event for the SSE hub. Returns nil when
// there's nothing to publish (insufficient data, solver failure).
func tryGeolocate(c *Cluster) []byte {
	usable := make([]MlatObservation, 0, len(c.Observations))
	for _, o := range c.Observations {
		if o.StationTNs == 0 || o.StationLat == 0 || o.StationLon == 0 {
			continue
		}
		// Drop observations from very-poorly-disciplined clocks; with
		// 50 ms+ accuracy class the solver result is dominated by that
		// station's noise. 100 ms is a generous threshold.
		if o.StationTAccNs > 100_000_000 {
			continue
		}
		usable = append(usable, MlatObservation{
			StationName: o.Station, Lat: o.StationLat, Lon: o.StationLon,
			AltM: o.StationAltM, TNs: o.StationTNs, TAccNs: o.StationTAccNs,
		})
	}
	if len(usable) < 3 {
		return nil
	}
	res, err := Solve(usable)
	if err != nil {
		return nil
	}
	out := struct {
		Event        string  `json:"event"`
		From         string  `json:"from"`
		PacketID     uint32  `json:"packet_id"`
		Lat          float64 `json:"lat"`
		Lon          float64 `json:"lon"`
		UncertaintyM float64 `json:"uncertainty_m"`
		StationCount int     `json:"station_count"`
		Iterations   int     `json:"iterations"`
	}{
		Event:        "GEOLOCATED",
		From:         c.Frame.From,
		PacketID:     c.Frame.PacketID,
		Lat:          res.Lat,
		Lon:          res.Lon,
		UncertaintyM: res.UncertaintyM,
		StationCount: res.StationCount,
		Iterations:   res.Iterations,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}
