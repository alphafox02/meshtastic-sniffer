// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/clocksync.go: cross-station clock-offset estimation from
// known-position anchor transmissions.
//
// Volunteer aviation MLAT networks (FlightAware, OpenSky) reach
// useful position accuracy without GPSDO at every receiver by
// solving relative clock offsets from observations of transmitters
// at known positions. For each pair of stations that both hear the
// same anchor packet:
//
//     measured_dt  = clock_offset_AB + propagation_dt_AB
//     expected_dt  = (dist(anchor, B) - dist(anchor, A)) / c
//     offset_AB    = measured_dt - expected_dt
//
// The anchor's known coordinates separate clock offset from
// propagation delay. WITHOUT a known anchor, the two are entangled
// in one equation and pairwise averaging over unknown-emitter
// traffic silently bakes geometry into the clock estimate -- a
// failure mode this module deliberately refuses to support in v1.
//
// Design constraints:
//
//   - anchor-gated: only transmissions from operator-declared anchor
//     nodes feed the pair-offset graph. Random Meshtastic traffic is
//     consumed for solving but NEVER for clock-sync calibration.
//
//   - robust pairwise median + MAD: each station pair maintains a
//     rolling buffer of recent offset measurements. Median is the
//     reported offset; MAD is the residual. Outlier samples don't
//     move the median much.
//
//   - explicit status: a pair is `warming` until min-N samples have
//     accumulated; `converged` when min-N is met AND MAD residual is
//     under threshold; `stale` when the most recent sample is older
//     than max-age; `rejected` if the residual stays above threshold.
//
//   - RSSI sanity gate: an observation whose RSSI is implausibly
//     strong (default >= -20 dBm) suggests near-field saturation /
//     compression and is rejected with a counter increment. Operators
//     get a runtime signal that anchor placement is too close to a
//     sniffer.
//
//   - distance sanity warning at config load: anchors closer than
//     30 m to any registered sniffer station log a warning naming
//     the affected pair.

package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"sync"
	"time"
)

// debugOn is set when MESHTASTIC_CLOCK_SYNC_DEBUG is non-empty.
// Logs every anchor-cluster FeedCluster call and the resulting pair
// state so tests can diagnose convergence failures.
var debugOn = os.Getenv("MESHTASTIC_CLOCK_SYNC_DEBUG") != ""

// AnchorType labels how the anchor's coordinates were obtained.
// Currently all v1 anchors are operator-declared; future sources
// (solver-promoted, sniffer-self-position) will use distinct labels.
type AnchorType uint8

const (
	AnchorDeclared       AnchorType = iota // CLI / config file lat/lon
	AnchorColocated                        // co-located with a registered sniffer
	AnchorPromotedSolved                   // promoted from a high-confidence solve (v1.1+)
)

func (t AnchorType) String() string {
	switch t {
	case AnchorDeclared:
		return "known_position"
	case AnchorColocated:
		return "colocated"
	case AnchorPromotedSolved:
		return "solved_event"
	}
	return "unknown"
}

// AnchorNode is one operator-declared transmitter at a known position.
type AnchorNode struct {
	NodeID     string // Meshtastic from-id, e.g. "!abcd1234"
	Lat        float64
	Lon        float64
	AltM       float64
	Type       AnchorType
	AccuracyNs float64 // declared timing accuracy of this anchor; 0 = use solver default
}

// PairKey returns a deterministic station-pair key.
func PairKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

// PairOffset is the rolling-state for one station pair.
type PairOffset struct {
	A, B          string
	Samples       []float64 // recent offset measurements (nanoseconds)
	SampleTimes   []time.Time
	MedianNs      float64 // robust pair-offset estimate
	MadNs         float64 // median-absolute-deviation residual
	LastUpdate    time.Time
	AnchorEvents  int    // count of anchor observations contributing
	AnchorIDs     map[string]int // breakdown by which anchor contributed
	Status        ClockSyncStatus
	RejectedRSSI  int // observations skipped by RSSI sanity gate
}

// ClockSyncStatus is the lifecycle state of a station-pair offset.
type ClockSyncStatus uint8

const (
	ClockSyncNone       ClockSyncStatus = iota // never had any anchor observation
	ClockSyncWarming                           // has some samples but not enough
	ClockSyncConverged                         // min-N met AND MAD < threshold
	ClockSyncStale                             // converged but most recent sample > max-age
	ClockSyncRejected                          // min-N met but MAD persistently > threshold
)

func (s ClockSyncStatus) String() string {
	switch s {
	case ClockSyncNone:
		return "none"
	case ClockSyncWarming:
		return "warming"
	case ClockSyncConverged:
		return "converged"
	case ClockSyncStale:
		return "stale"
	case ClockSyncRejected:
		return "rejected"
	}
	return "unknown"
}

// ClockSyncConfig is the tuning knob bundle.
type ClockSyncConfig struct {
	MinAnchorEvents int           // samples required before "converged" (default 10)
	MaxMADNs        float64       // MAD threshold for converged (default 5000 ns = 5 us)
	MaxAgeS         float64       // expire samples older than this (default 600 s)
	MaxSamples      int           // ring size per pair (default 64)
	MaxRSSIdBm      float64       // RSSI sanity gate; reject stronger (default -20 dBm)
	MinDistanceM    float64       // startup warning threshold (default 30 m)
}

// DefaultClockSyncConfig returns the v1 defaults.
func DefaultClockSyncConfig() ClockSyncConfig {
	return ClockSyncConfig{
		MinAnchorEvents: 10,
		MaxMADNs:        5000.0,
		MaxAgeS:         600.0,
		MaxSamples:      64,
		MaxRSSIdBm:      -20.0,
		MinDistanceM:    30.0,
	}
}

// ClockSync is the per-fusion-process clock-sync state.
type ClockSync struct {
	anchors map[string]AnchorNode      // keyed by from-id
	pairs   map[string]*PairOffset     // keyed by PairKey
	config  ClockSyncConfig
	mu      sync.RWMutex
	stats   ClockSyncStats
}

// ClockSyncStats are runtime counters exposed for dashboards / logs.
type ClockSyncStats struct {
	AnchorsDeclared       int
	ObservationsFed       int
	ObservationsRSSIGated int
	PairsKnown            int
	PairsConverged        int
}

// NewClockSync returns an empty clock-sync state with the given config.
func NewClockSync(cfg ClockSyncConfig) *ClockSync {
	return &ClockSync{
		anchors: make(map[string]AnchorNode),
		pairs:   make(map[string]*PairOffset),
		config:  cfg,
	}
}

// AddAnchor registers an anchor node. Returns an error if the node-id
// is already registered (operators should explicitly remove first).
func (cs *ClockSync) AddAnchor(a AnchorNode) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, dup := cs.anchors[a.NodeID]; dup {
		return fmt.Errorf("anchor %q already registered", a.NodeID)
	}
	cs.anchors[a.NodeID] = a
	cs.stats.AnchorsDeclared = len(cs.anchors)
	return nil
}

// LookupAnchor returns the anchor for the given from-id, or false.
func (cs *ClockSync) LookupAnchor(fromID string) (AnchorNode, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	a, ok := cs.anchors[fromID]
	return a, ok
}

// CheckAnchorPlacement walks every (anchor, sniffer-station) pair and
// returns a slice of warnings naming pairs closer than MinDistanceM.
// Called once at startup against the sniffer-station registry.
type stationCoord struct {
	Name string
	Lat  float64
	Lon  float64
}

func (cs *ClockSync) CheckAnchorPlacement(stations []stationCoord) []string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var warnings []string
	for _, a := range cs.anchors {
		if a.Type == AnchorColocated {
			continue // co-located anchors are intentionally close to ONE station
		}
		for _, s := range stations {
			if s.Lat == 0 && s.Lon == 0 {
				continue // station with unknown coords
			}
			distM := haversineM(a.Lat, a.Lon, s.Lat, s.Lon)
			if distM < cs.config.MinDistanceM {
				warnings = append(warnings, fmt.Sprintf(
					"anchor %s is %.1f m from sniffer station %q (<%.0f m). "+
						"Clock-sync samples from this pair will likely be biased "+
						"by near-field / front-end saturation. "+
						"See docs/clock-sync.md#anchor-placement.",
					a.NodeID, distM, s.Name, cs.config.MinDistanceM))
			}
		}
	}
	return warnings
}

// haversineM computes great-circle distance in meters between two
// (lat,lon) points. Accurate for the ranges relevant to a LoRa mesh.
func haversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthR = 6371000.0
	rlat1 := lat1 * math.Pi / 180.0
	rlat2 := lat2 * math.Pi / 180.0
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rlat1)*math.Cos(rlat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthR * c
}

// distMeters from station to anchor using the same ENU approximation
// the solver uses (flat-earth equirectangular). Sufficient for the
// short baselines clock-sync targets.
func distMeters(anchorLat, anchorLon, stationLat, stationLon float64) float64 {
	return haversineM(anchorLat, anchorLon, stationLat, stationLon)
}

// FeedCluster examines a flushed Cluster (all observations of one
// (from, packet_id)) and -- if the from-id is a declared anchor --
// updates pair-offset state for every station pair that heard it.
//
// Non-anchor clusters are silently skipped: clock-sync calibration
// only consumes operator-anchored traffic. The caller is responsible
// for filtering on cluster.Frame.From; this method does the lookup
// itself for clarity.
func (cs *ClockSync) FeedCluster(c *Cluster) {
	if c == nil || len(c.Observations) < 2 {
		return
	}
	cs.mu.RLock()
	anchor, ok := cs.anchors[c.Frame.From]
	cfg := cs.config
	cs.mu.RUnlock()
	if !ok {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.stats.ObservationsFed += len(c.Observations)
	usable := make([]Observation, 0, len(c.Observations))
	for _, o := range c.Observations {
		// Must have a precise per-frame lock timestamp to be useful.
		if o.PreambleLockTNs == 0 {
			continue
		}
		// RSSI sanity: reject implausibly-strong observations that
		// suggest near-field saturation. Threshold is operator-tunable.
		if o.RssiDB != 0 && o.RssiDB > cfg.MaxRSSIdBm {
			cs.stats.ObservationsRSSIGated++
			continue
		}
		usable = append(usable, o)
	}
	if len(usable) < 2 {
		return
	}
	now := time.Now()
	for i := 0; i < len(usable); i++ {
		for j := i + 1; j < len(usable); j++ {
			A := usable[i]
			B := usable[j]
			measuredDtNs := float64(int64(B.PreambleLockTNs) - int64(A.PreambleLockTNs))
			distA := distMeters(anchor.Lat, anchor.Lon, A.StationLat, A.StationLon)
			distB := distMeters(anchor.Lat, anchor.Lon, B.StationLat, B.StationLon)
			expectedDtNs := (distB - distA) / speedOfLight * 1e9
			offsetNs := measuredDtNs - expectedDtNs

			key := PairKey(A.Station, B.Station)
			po, ok := cs.pairs[key]
			if !ok {
				po = &PairOffset{
					A: A.Station, B: B.Station,
					AnchorIDs: make(map[string]int),
				}
				if PairKey(A.Station, B.Station) == A.Station+"|"+B.Station {
					po.A, po.B = A.Station, B.Station
				} else {
					po.A, po.B = B.Station, A.Station
					offsetNs = -offsetNs // flip sign to match canonical pair order
				}
				cs.pairs[key] = po
			} else if po.A != A.Station {
				// Existing pair ordered the other way; flip sign so the
				// stored offset is always (po.B time - po.A time).
				offsetNs = -offsetNs
			}
			po.Samples = append(po.Samples, offsetNs)
			po.SampleTimes = append(po.SampleTimes, now)
			po.AnchorEvents++
			po.AnchorIDs[anchor.NodeID]++
			po.LastUpdate = now
			// Cap ring size: drop oldest.
			if len(po.Samples) > cfg.MaxSamples {
				drop := len(po.Samples) - cfg.MaxSamples
				po.Samples = po.Samples[drop:]
				po.SampleTimes = po.SampleTimes[drop:]
			}
			// Age out samples older than MaxAgeS.
			cutoff := now.Add(-time.Duration(cfg.MaxAgeS * float64(time.Second)))
			keepFrom := 0
			for k, t := range po.SampleTimes {
				if t.After(cutoff) {
					keepFrom = k
					break
				}
				keepFrom = k + 1
			}
			if keepFrom > 0 {
				po.Samples = po.Samples[keepFrom:]
				po.SampleTimes = po.SampleTimes[keepFrom:]
			}
			po.recomputeMedianMAD()
			po.updateStatus(cfg)
		}
	}
	cs.stats.PairsKnown = len(cs.pairs)
	conv := 0
	for _, po := range cs.pairs {
		if po.Status == ClockSyncConverged {
			conv++
		}
	}
	cs.stats.PairsConverged = conv
	if debugOn {
		for _, po := range cs.pairs {
			log.Printf("clock-sync DBG: anchor=%s pair=%s|%s n=%d median=%.1fns mad=%.1fns status=%s",
				c.Frame.From, po.A, po.B, len(po.Samples), po.MedianNs, po.MadNs, po.Status)
		}
	}
}

// recomputeMedianMAD updates the pair's robust statistics from
// current samples. Must be called with the parent ClockSync.mu held.
func (po *PairOffset) recomputeMedianMAD() {
	if len(po.Samples) == 0 {
		po.MedianNs = 0
		po.MadNs = 0
		return
	}
	cp := make([]float64, len(po.Samples))
	copy(cp, po.Samples)
	sort.Float64s(cp)
	po.MedianNs = cp[len(cp)/2]
	// MAD: median of |sample - median|.
	devs := make([]float64, len(cp))
	for i, v := range cp {
		devs[i] = math.Abs(v - po.MedianNs)
	}
	sort.Float64s(devs)
	po.MadNs = devs[len(devs)/2]
}

// updateStatus transitions the pair's status based on current
// sample count and MAD residual.
func (po *PairOffset) updateStatus(cfg ClockSyncConfig) {
	if po.AnchorEvents == 0 {
		po.Status = ClockSyncNone
		return
	}
	if len(po.Samples) < cfg.MinAnchorEvents {
		po.Status = ClockSyncWarming
		return
	}
	if po.MadNs > cfg.MaxMADNs {
		po.Status = ClockSyncRejected
		return
	}
	cutoff := time.Now().Add(-time.Duration(cfg.MaxAgeS * float64(time.Second)))
	if po.LastUpdate.Before(cutoff) {
		po.Status = ClockSyncStale
		return
	}
	po.Status = ClockSyncConverged
}

// CorrectAndClassify returns the timestamp this observation should
// use for the solver, along with the corresponding TimestampClass.
//
//   - If the station has a converged pair-offset to ANY other station
//     in the network, the returned class is `sync` and the timestamp
//     is `PreambleLockTNs` adjusted by half the pair offset toward
//     a network reference. v1 uses the simplest possible policy: the
//     converged station with the smallest station name (lexicographic)
//     is treated as the reference, and other stations have their
//     timestamps shifted by the median pair-offset to that reference.
//
//   - If no pair-offset has converged for this station, return the
//     raw PreambleLockTNs and class=software_lock.
//
//   - If PreambleLockTNs is zero, return StationTNs and class=frame.
//
// The reference-station policy keeps v1 simple and inspectable; a
// graph-optimization upgrade can replace this without changing the
// solver's downstream contract.
func (cs *ClockSync) CorrectAndClassify(obs Observation, refStation string) (uint64, TimestampClass) {
	if obs.PreambleLockTNs == 0 {
		return obs.StationTNs, TimestampFrame
	}
	if refStation == "" || refStation == obs.Station {
		// Reference station's own observations need no correction.
		// If we have any converged pair touching this station, label sync.
		if cs.stationHasConvergedPair(obs.Station) {
			return obs.PreambleLockTNs, TimestampSync
		}
		return obs.PreambleLockTNs, TimestampSoftwareLock
	}
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	key := PairKey(obs.Station, refStation)
	po, ok := cs.pairs[key]
	if !ok || pairStatusNow(po, cs.config) != ClockSyncConverged {
		return obs.PreambleLockTNs, TimestampSoftwareLock
	}
	// Shift this observation's time onto the reference station's clock.
	// po.MedianNs is signed: (po.B time - po.A time). If this obs is on
	// po.A side, subtract; if on po.B side, add. (Equivalently: shift
	// THIS observation by the offset that makes it match what refStation
	// would have measured.)
	corrected := int64(obs.PreambleLockTNs)
	if obs.Station == po.A && refStation == po.B {
		corrected += int64(po.MedianNs)
	} else {
		corrected -= int64(po.MedianNs)
	}
	if corrected < 0 {
		corrected = 0
	}
	return uint64(corrected), TimestampSync
}

func (cs *ClockSync) stationHasConvergedPair(station string) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for _, po := range cs.pairs {
		if (po.A == station || po.B == station) && pairStatusNow(po, cs.config) == ClockSyncConverged {
			return true
		}
	}
	return false
}

// pairStatusNow returns the pair's current status taking aging into
// account. updateStatus() only runs inside FeedCluster (when an anchor
// cluster arrives); if no anchor traffic has arrived for a while,
// po.Status may still be ClockSyncConverged in memory even though
// every sample has aged out. Anyone reading the status to decide a
// solve's timestamp class needs the now-evaluated result, not the
// last-write-time snapshot.
func pairStatusNow(po *PairOffset, cfg ClockSyncConfig) ClockSyncStatus {
	if po.AnchorEvents == 0 {
		return ClockSyncNone
	}
	if len(po.Samples) < cfg.MinAnchorEvents {
		return ClockSyncWarming
	}
	if po.MadNs > cfg.MaxMADNs {
		return ClockSyncRejected
	}
	cutoff := time.Now().Add(-time.Duration(cfg.MaxAgeS * float64(time.Second)))
	if po.LastUpdate.Before(cutoff) {
		return ClockSyncStale
	}
	return ClockSyncConverged
}

// PickReferenceStation returns the lexicographically smallest station
// name that participates in at least one converged pair. Returns ""
// when no pair has converged. Uses pairStatusNow() so a pair whose
// samples have aged out doesn't get picked as a stale reference.
func (cs *ClockSync) PickReferenceStation() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var ref string
	for _, po := range cs.pairs {
		if pairStatusNow(po, cs.config) != ClockSyncConverged {
			continue
		}
		for _, name := range []string{po.A, po.B} {
			if ref == "" || name < ref {
				ref = name
			}
		}
	}
	return ref
}

// IsAnchor reports whether a packet's from-id is in the anchor registry.
// Used by the cluster-flush path to suppress GEOLOCATED emission for
// anchor traffic (it's calibration data, not a target to locate).
func (cs *ClockSync) IsAnchor(fromID string) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	_, ok := cs.anchors[fromID]
	return ok
}

// Snapshot returns a defensive copy of the runtime stats.
func (cs *ClockSync) Snapshot() ClockSyncStats {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.stats
}

// PairSnapshot returns a defensive copy of one pair's state, or nil
// if the pair is unknown. Used by the dashboard / per-solve labeling.
type PairSnapshot struct {
	A, B           string
	MedianNs       float64
	MadNs          float64
	AnchorEvents   int
	Status         string
	LastUpdateSAgo float64
}

func (cs *ClockSync) PairSnapshotByStations(a, b string) *PairSnapshot {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	po, ok := cs.pairs[PairKey(a, b)]
	if !ok {
		return nil
	}
	ageS := 0.0
	if !po.LastUpdate.IsZero() {
		ageS = time.Since(po.LastUpdate).Seconds()
	}
	return &PairSnapshot{
		A: po.A, B: po.B,
		MedianNs:       po.MedianNs,
		MadNs:          po.MadNs,
		AnchorEvents:   po.AnchorEvents,
		Status:         po.Status.String(),
		LastUpdateSAgo: ageS,
	}
}
