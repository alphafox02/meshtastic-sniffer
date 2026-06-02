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
	StationTNs     uint64  `json:"station_t_ns,omitempty"`     /* sensor capture timestamp (ns since epoch) -- frame-emit time */
	StationTAccNs  uint32  `json:"station_t_acc_ns,omitempty"` /* clock-discipline class for mlat weighting */
	/* TDOA software-lock timestamp: CLOCK_REALTIME at the moment the
	 * sensor detected the preamble. Strictly earlier in the pipeline
	 * than station_t_ns (which the sensor stamps after the whole
	 * frame demodulates), so much closer to the actual time-of-arrival
	 * for mlat purposes. NOT a sample-derived GPSDO-grade TOA; PFB /
	 * scheduling / buffering latency are still baked in. */
	PreambleLockTNs uint64 `json:"preamble_lock_t_ns,omitempty"`
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
	/* Radio-layer parameters needed for cluster_observations replay
	 * persistence. Emitted by the sniffer on every frame event since
	 * the per-slot freq metadata wire-up; safe to leave 0 for older
	 * feeds. */
	SF     int    `json:"sf,omitempty"`
	CR     int    `json:"cr,omitempty"`
	BwHz   int    `json:"bw_hz,omitempty"`
	FreqHz uint64 `json:"freq_hz,omitempty"`
	Decrypted      *bool   `json:"decrypted,omitempty"`
	PortName       string  `json:"port_name,omitempty"`
}

// Observation is one (station, frame) tuple inside a cluster.
type Observation struct {
	Station         string
	StationLat      float64
	StationLon      float64
	StationAltM     float64
	StationTNs      uint64 /* frame-emit timestamp ("frame" class) */
	StationTAccNs   uint32
	PreambleLockTNs uint64 /* preamble-detect timestamp ("software_lock" class) */
	SnrDB           float64
	RssiDB          float64
	At              time.Time
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

// toClusterObservationRecord projects a runtime Cluster into the
// on-disk shape persisted to the cluster_observations bbolt bucket.
// ClusterTimeNs is the RF event anchor: the max of per-observation
// preamble_lock_t_ns when any sniffer published it; falls back to the
// cluster's first-seen wall-clock for older feeds. Sortable timestamps
// let the replay path do time-range scans without rewalking the world.
func toClusterObservationRecord(c *Cluster) *ClusterObservationRecord {
	rec := &ClusterObservationRecord{
		From:            c.Frame.From,
		PacketID:        c.Frame.PacketID,
		FirstSeenWallNs: uint64(c.FirstSeen.UnixNano()),
		Preset:          c.Frame.Preset,
		SF:              c.Frame.SF,
		CR:              c.Frame.CR,
		BwHz:            c.Frame.BwHz,
		FreqHz:          c.Frame.FreqHz,
		ChannelName:     c.Frame.ChannelName,
	}
	for _, o := range c.Observations {
		rec.Observations = append(rec.Observations, ClusterObservationStation{
			Station: o.Station, StationLat: o.StationLat, StationLon: o.StationLon,
			StationAltM:    o.StationAltM,
			StationTNs:     o.StationTNs,
			StationTAccNs:  o.StationTAccNs,
			PreambleLockTNs: o.PreambleLockTNs,
			SnrDB:          o.SnrDB,
			RssiDB:         o.RssiDB,
		})
		if o.PreambleLockTNs > rec.ClusterTimeNs {
			rec.ClusterTimeNs = o.PreambleLockTNs
		}
	}
	if rec.ClusterTimeNs == 0 {
		// Fall back to wall-clock event time when no sniffer supplied
		// preamble_lock_t_ns (pre-5e9a1fc feeds, or selftest events).
		rec.ClusterTimeNs = rec.FirstSeenWallNs
	}
	return rec
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
	calibrationCfg := flag.String("calibration-config", "",
		"Path to anchor registry JSON ([{from_id, lat, lon, alt_m, accuracy_ns}, ...]) for clock-sync calibration. Anchor traffic feeds the clock-sync graph; arbitrary traffic does not. Empty = clock-sync disabled.")
	calibrationFlag := stringSlice{}
	flag.Var(&calibrationFlag, "calibration-node",
		"Anchor declaration as from_id:lat=X:lon=Y[:alt=A][:accuracy_ns=N]. Repeatable. Composes with --calibration-config.")
	clockSyncOn := flag.String("clock-sync", "auto",
		"Clock-sync mode: on | off | auto (default: enabled iff any anchor declared)")
	clockSyncMinN := flag.Int("clock-sync-min-n", 10,
		"Min anchor observations before a pair is labeled converged.")
	clockSyncMaxMADNs := flag.Float64("clock-sync-max-mad-ns", 5000.0,
		"Max MAD residual (ns) for a pair to be labeled converged.")
	clockSyncMaxAgeS := flag.Float64("clock-sync-max-age-s", 600.0,
		"Expire pair samples older than this; converged pair becomes stale.")
	clockSyncMaxRSSI := flag.Float64("clock-sync-max-rssi-dbm", -20.0,
		"RSSI sanity gate: reject anchor observations stronger than this (near-field/saturation).")
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

	// Build the clock-sync state. Anchor traffic feeds the pair-offset
	// graph; everything else is consumed for solving only. See
	// docs/clock-sync.md for the operator-facing details.
	csCfg := DefaultClockSyncConfig()
	csCfg.MinAnchorEvents = *clockSyncMinN
	csCfg.MaxMADNs = *clockSyncMaxMADNs
	csCfg.MaxAgeS = *clockSyncMaxAgeS
	csCfg.MaxRSSIdBm = *clockSyncMaxRSSI
	globalClockSync = NewClockSync(csCfg)
	if err := loadAnchorConfig(*calibrationCfg, calibrationFlag, globalClockSync); err != nil {
		log.Fatalf("calibration: %v", err)
	}
	csStats := globalClockSync.Snapshot()
	switch *clockSyncOn {
	case "off":
		globalClockSync = nil
		log.Printf("clock-sync: disabled (--clock-sync=off)")
	case "on":
		if csStats.AnchorsDeclared == 0 {
			log.Printf("clock-sync: enabled but NO anchors declared; pair offsets will never converge")
		} else {
			log.Printf("clock-sync: enabled with %d anchor(s)", csStats.AnchorsDeclared)
		}
	default: // "auto"
		if csStats.AnchorsDeclared == 0 {
			globalClockSync = nil
			log.Printf("clock-sync: auto disabled (no anchors declared)")
		} else {
			log.Printf("clock-sync: auto enabled with %d anchor(s)", csStats.AnchorsDeclared)
		}
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

	// Anchor-placement sanity check: warn (don't refuse) when any
	// declared anchor is closer than MinDistanceM to a registered
	// sniffer station's coords. Near-field / front-end saturation
	// will bias clock-sync samples even though the math itself
	// works. Co-located anchors (Type=AnchorColocated) are
	// intentionally close to one station and exempt from this check.
	if globalClockSync != nil {
		var stations []stationCoord
		for _, s := range registry.List() {
			if s.Lat == 0 && s.Lon == 0 {
				continue
			}
			stations = append(stations, stationCoord{Name: s.Name, Lat: s.Lat, Lon: s.Lon})
		}
		for _, w := range globalClockSync.CheckAnchorPlacement(stations) {
			log.Printf("WARN clock-sync: %s", w)
		}
	}

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
				StationAltM: f.StationAltM, StationTNs: f.StationTNs,
				StationTAccNs: f.StationTAccNs, PreambleLockTNs: f.PreambleLockTNs,
				SnrDB: f.SnrDB, RssiDB: f.RssiDB, At: now,
			})
		case now := <-tick.C:
			ready := flushReady(pending, *window, now)
			for _, c := range ready {
				printCluster(c, registry.pool.EndpointCount())
				/* Persist the cluster's raw evidence so a future
				 * replay/re-solve has the same per-station inputs the
				 * live solver consumed. Best-effort: errors are
				 * logged but never block the live publish path. No-op
				 * when state DB is not attached. */
				if store != nil {
					if err := store.WriteClusterObservation(toClusterObservationRecord(c)); err != nil {
						log.Printf("cluster_observations: %v", err)
					}
				}
				/* Feed clock-sync with anchor-cluster pair offsets BEFORE
				 * solving any non-anchor cluster. Clock-sync silently
				 * skips clusters whose from-id is not in the registry.
				 * Returned snapshots persist the per-pair state at
				 * the RF event time of this anchor cluster, so replay
				 * can later answer "what offsets were valid here?" */
				if globalClockSync != nil {
					snapshots := globalClockSync.FeedCluster(c)
					if store != nil {
						for i := range snapshots {
							if err := store.WritePairSnapshot(&snapshots[i]); err != nil {
								log.Printf("pair_snapshots: %v", err)
							}
						}
					}
				}
				if hub != nil {
					if b, err := txEventJSON(c, registry.pool.EndpointCount()); err == nil {
						hub.Publish(b)
					}
					/* Multilateration: when 3+ observations carry station
					 * positions and timestamps, run the solver and publish
					 * a GEOLOCATED event alongside the TX consolidation.
					 * Anchor traffic is calibration data, not a target --
					 * suppress GEOLOCATED for declared anchors. */
					if globalClockSync == nil || !globalClockSync.IsAnchor(c.Frame.From) {
						if g := tryGeolocate(c); g != nil {
							hub.Publish(g)
						}
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
	// If clock-sync is active and at least one pair touching this
	// cluster has converged, apply the median pair offset to shift
	// per-station timestamps onto a common network reference clock.
	var refStation string
	if globalClockSync != nil {
		refStation = globalClockSync.PickReferenceStation()
	}
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
		// Apply clock-sync correction when available; the returned
		// class drives the MlatResult's per-observation labeling.
		lockTNs := o.PreambleLockTNs
		var precClass TimestampClass
		hasClass := false
		if globalClockSync != nil && refStation != "" {
			lockTNs, precClass = globalClockSync.CorrectAndClassify(o, refStation)
			hasClass = true
		}
		usable = append(usable, MlatObservation{
			StationName: o.Station, Lat: o.StationLat, Lon: o.StationLon,
			AltM:                o.StationAltM,
			TNs:                 o.StationTNs,
			LockTNs:             lockTNs,
			TAccNs:              o.StationTAccNs,
			PrecomputedClass:    precClass,
			HasPrecomputedClass: hasClass,
		})
	}
	if len(usable) < 3 {
		return nil
	}
	res, err := Solve(usable)
	if err != nil {
		return nil
	}
	// Tag the result with the dominant class observed across all
	// usable observations, and surface clock-sync diagnostics if any
	// pairs were converged.
	if globalClockSync != nil && refStation != "" {
		pairCount, maxMAD := 0, 0.0
		anchorIDs := map[string]struct{}{}
		// Count each (non-reference) station whose pair to refStation
		// is converged. The reference itself counts as part of every
		// converged pair touching it, so it doesn't get a "pair" entry
		// on its own row. Cluster.Observations ordering is not aligned
		// with refStation; iterate all and skip refStation explicitly.
		for _, o := range c.Observations {
			if o.StationTNs == 0 || o.StationLat == 0 || o.StationLon == 0 {
				continue
			}
			if o.Station == refStation {
				continue
			}
			_, cls := globalClockSync.CorrectAndClassify(o, refStation)
			if cls != TimestampSync {
				continue
			}
			if snap := globalClockSync.PairSnapshotByStations(refStation, o.Station); snap != nil {
				pairCount++
				if snap.MadNs > maxMAD {
					maxMAD = snap.MadNs
				}
			}
		}
		// Tally anchors that contributed to any pair STILL converged at
		// read time (uses pairStatusNow so a stale pair doesn't get
		// credited for the anchor that fed it minutes ago).
		globalClockSync.mu.RLock()
		for _, po := range globalClockSync.pairs {
			if pairStatusNow(po, globalClockSync.config) != ClockSyncConverged {
				continue
			}
			for id := range po.AnchorIDs {
				anchorIDs[id] = struct{}{}
			}
		}
		globalClockSync.mu.RUnlock()
		res.ClockSyncPairCount = pairCount
		res.ClockSyncResidualNs = maxMAD
		res.ClockSyncAnchorCount = len(anchorIDs)
		res.ClockSyncReference = refStation
		if pairCount > 0 && res.WorstTimestampCls > TimestampSync {
			// Some observation downgraded; class stays "mixed"
			res.Degraded = true
		}
	}
	out := struct {
		Event                string  `json:"event"`
		From                 string  `json:"from"`
		PacketID             uint32  `json:"packet_id"`
		Lat                  float64 `json:"lat"`
		Lon                  float64 `json:"lon"`
		UncertaintyM         float64 `json:"uncertainty_m"`
		StationCount         int     `json:"station_count"`
		Iterations           int     `json:"iterations"`
		TimestampClass       string  `json:"timestamp_class"`
		Degraded             bool    `json:"timestamp_class_degraded,omitempty"`
		// Clock-sync diagnostics: always emit (no omitempty) when the
		// solve happened, so dashboard consumers don't have to guess
		// "field missing == 0?". A solve without clock-sync emits
		// zeros across the board, which is a distinct state from
		// "fields not present at all" in older sniffer-only feeds.
		ClockSyncPairCount   int     `json:"clock_sync_pair_count"`
		ClockSyncResidualNs  float64 `json:"clock_sync_residual_ns"`
		ClockSyncAnchorCount int     `json:"clock_sync_anchor_count"`
		ClockSyncReference   string  `json:"clock_sync_reference"`
	}{
		Event:                "GEOLOCATED",
		From:                 c.Frame.From,
		PacketID:             c.Frame.PacketID,
		Lat:                  res.Lat,
		Lon:                  res.Lon,
		UncertaintyM:         res.UncertaintyM,
		StationCount:         res.StationCount,
		Iterations:           res.Iterations,
		TimestampClass:       res.WorstTimestampCls.String(),
		Degraded:             res.Degraded,
		ClockSyncPairCount:   res.ClockSyncPairCount,
		ClockSyncResidualNs:  res.ClockSyncResidualNs,
		ClockSyncAnchorCount: res.ClockSyncAnchorCount,
		ClockSyncReference:   res.ClockSyncReference,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// globalClockSync is the per-process clock-sync state. nil when
// clock-sync is disabled at startup (no anchors declared and
// --clock-sync=auto, or --clock-sync=off explicitly).
var globalClockSync *ClockSync

// stringSlice is a flag.Var-compatible repeatable string flag.
type stringSlice []string

func (s *stringSlice) String() string         { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error     { *s = append(*s, v); return nil }

// loadAnchorConfig populates the clock-sync anchor registry from the
// optional config file path AND any --calibration-node CLI entries.
// CLI entries use the form "from_id:lat=X:lon=Y[:alt=A][:accuracy_ns=N]";
// the config file is a JSON array of AnchorNode-shaped records.
func loadAnchorConfig(path string, cliEntries []string, cs *ClockSync) error {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var anchors []AnchorNode
		if err := json.Unmarshal(raw, &anchors); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, a := range anchors {
			if a.NodeID == "" {
				return fmt.Errorf("anchor in %s missing node_id", path)
			}
			if err := cs.AddAnchor(a); err != nil {
				return fmt.Errorf("anchor %s: %w", a.NodeID, err)
			}
		}
	}
	for _, raw := range cliEntries {
		a, err := parseAnchorCLI(raw)
		if err != nil {
			return fmt.Errorf("--calibration-node %q: %w", raw, err)
		}
		if err := cs.AddAnchor(a); err != nil {
			return fmt.Errorf("anchor %s: %w", a.NodeID, err)
		}
	}
	return nil
}

// parseAnchorCLI parses "from_id:lat=X:lon=Y[:alt=A][:accuracy_ns=N]".
// Returns an AnchorNode of Type=AnchorDeclared. Order of key=val pairs
// after the from_id is free.
func parseAnchorCLI(s string) (AnchorNode, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 3 {
		return AnchorNode{}, fmt.Errorf("expected from_id:lat=X:lon=Y[:...]")
	}
	a := AnchorNode{NodeID: parts[0], Type: AnchorDeclared}
	sawLat, sawLon := false, false
	for _, kv := range parts[1:] {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return AnchorNode{}, fmt.Errorf("bad k=v: %q", kv)
		}
		k, v := kv[:eq], kv[eq+1:]
		switch k {
		case "lat":
			f, err := parseFloatTrim(v)
			if err != nil {
				return AnchorNode{}, fmt.Errorf("lat: %w", err)
			}
			a.Lat = f
			sawLat = true
		case "lon":
			f, err := parseFloatTrim(v)
			if err != nil {
				return AnchorNode{}, fmt.Errorf("lon: %w", err)
			}
			a.Lon = f
			sawLon = true
		case "alt", "alt_m":
			f, err := parseFloatTrim(v)
			if err != nil {
				return AnchorNode{}, fmt.Errorf("alt: %w", err)
			}
			a.AltM = f
		case "accuracy_ns":
			f, err := parseFloatTrim(v)
			if err != nil {
				return AnchorNode{}, fmt.Errorf("accuracy_ns: %w", err)
			}
			a.AccuracyNs = f
		default:
			return AnchorNode{}, fmt.Errorf("unknown key: %q", k)
		}
	}
	if !sawLat || !sawLon {
		return AnchorNode{}, fmt.Errorf("lat= and lon= are required")
	}
	return a, nil
}

func parseFloatTrim(v string) (float64, error) {
	v = strings.TrimSpace(v)
	var f float64
	_, err := fmt.Sscanf(v, "%g", &f)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", v)
	}
	return f, nil
}
