// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/replay.go: event-time re-solve endpoint.
//
// POST /api/resolve runs the MLAT solver against persisted evidence
// (cluster_observations) for a single past RF event, applying the
// pair-offset state that was current AT THAT EVENT TIME (loaded from
// pair_snapshots via LatestPairSnapshotAtOrBefore). The result is
// published as a distinct REPLAY_GEOLOCATED SSE event -- NOT reusing
// the live GEOLOCATED type -- so the dashboard timeline can render
// replays alongside live solves without conflating their semantics.
//
// Two replay modes are reserved on the wire:
//
//   mode = "event_time"     historical clock model at the RF event time.
//                           Safe default. Honest answer to "what would
//                           we have solved if we'd had this evidence
//                           when it happened?"
//
//   mode = "current_model"  TODAY's clock model applied to OLD evidence.
//                           Useful for experiments but dangerous as an
//                           operator default; UI gates this behind an
//                           Advanced disclosure with a confirmation.
//                           Landing in a follow-up commit.
//
// Replay results are NOT persisted to solved_fixes; solved_fixes is
// reserved for the live solve path. A replay is an ephemeral derivation
// the operator can re-run.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ResolveRequest is the POST /api/resolve wire format. Fields mirror
// the timeline-row keys the Evidence tab already has, so the UI button
// just forwards what it already knows.
//
// EventTimeNs is decoded via UnmarshalJSON to accept either a JSON
// number or a JSON string. The browser must send a string for any
// timestamp past JS's safe-integer range (~9e15) -- a JSON number would
// be silently rounded before transit and the backend's 1 ns key lookup
// would miss the row.
type ResolveRequest struct {
	From        string `json:"from"`
	PacketID    uint32 `json:"packet_id"`
	EmissionSeq int    `json:"emission_seq,omitempty"`
	EventTimeNs uint64 `json:"event_time_ns"`
	Mode        string `json:"mode,omitempty"` // "event_time" (default) | "current_model" (Advanced)
}

// UnmarshalJSON accepts event_time_ns as either a JSON number or a
// base-10 JSON string so callers that care about precision can send
// the string form. Other fields decode through the normal struct path.
func (req *ResolveRequest) UnmarshalJSON(data []byte) error {
	type rawReq struct {
		From        string          `json:"from"`
		PacketID    uint32          `json:"packet_id"`
		EmissionSeq int             `json:"emission_seq,omitempty"`
		EventTimeNs json.RawMessage `json:"event_time_ns"`
		Mode        string          `json:"mode,omitempty"`
	}
	var r rawReq
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	req.From = r.From
	req.PacketID = r.PacketID
	req.EmissionSeq = r.EmissionSeq
	req.Mode = r.Mode
	raw := strings.TrimSpace(string(r.EventTimeNs))
	if raw == "" || raw == "null" {
		req.EventTimeNs = 0
		return nil
	}
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("event_time_ns: %w", err)
	}
	req.EventTimeNs = n
	return nil
}

func (req *ResolveRequest) eventID() string {
	return fmt.Sprintf("%s|%d|%d|%d", req.From, req.PacketID, req.EmissionSeq, req.EventTimeNs)
}

// pairKeyEndpoints splits a "A|B" pair key into (A, B). PairKey
// guarantees A < B lexicographically.
func pairKeyEndpoints(pk string) (string, string, bool) {
	i := strings.IndexByte(pk, '|')
	if i <= 0 || i >= len(pk)-1 {
		return "", "", false
	}
	return pk[:i], pk[i+1:], true
}

// findClusterObservation walks the cluster_observations bucket within a
// tight time window around eventTimeNs and returns the row matching
// (from, packetID, emissionSeq). Returns (nil, nil) when nothing
// matches -- distinct from an IO error.
func findClusterObservation(store *EventStore, eventTimeNs uint64, from string,
	packetID uint32, emissionSeq int,
) (*ClusterObservationRecord, error) {
	if store == nil {
		return nil, errors.New("no state-db")
	}
	// Range scan a 1-ns window. The key encoding puts cluster_time_ns
	// first; the bucket only stores integers, so [N,N] catches at most
	// the rows at exactly that nanosecond. The cluster_obs key shape is
	// (clusterTimeNs, from, packetID) -- distinct emissions of the same
	// (from, packetID) live at distinct cluster_time_ns by construction
	// of the same-emission rule, so emission_seq is for disambiguation
	// inside the record body, not the key.
	recs, err := store.ReadClusterObservationsRange(eventTimeNs, eventTimeNs)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		r := &recs[i]
		if r.From == from && r.PacketID == packetID && r.EmissionSeq == emissionSeq {
			return r, nil
		}
	}
	return nil, nil
}

// resolveAtEventTime re-runs the MLAT solver over `rec` using the
// pair-offset snapshot that was current at rec.ClusterTimeNs. The
// reference station is the lexicographically smallest station that
// participated; per-station observations on the non-reference side get
// shifted by the snapshot's median pair-offset toward the reference's
// clock frame, matching the live CorrectAndClassify shape.
//
// Returns the solver result, the pair-snapshot keys actually consulted
// (for the SSE event's audit trail), and the chosen reference station.
// Errors when the cluster has fewer than three usable observations or
// the solver fails to converge.
func resolveAtEventTime(store *EventStore, rec *ClusterObservationRecord) (
	*MlatResult, []string, string, error,
) {
	if rec == nil {
		return nil, nil, "", errors.New("nil record")
	}
	if store == nil {
		return nil, nil, "", errors.New("no state-db")
	}
	eventTimeNs := rec.ClusterTimeNs

	// Filter usable observations (same gates the live path uses).
	type usableObs struct {
		o   ClusterObservationStation
		idx int
	}
	var usable []usableObs
	for i, o := range rec.Observations {
		if o.StationTNs == 0 || o.StationLat == 0 || o.StationLon == 0 {
			continue
		}
		if o.StationTAccNs > 100_000_000 {
			continue
		}
		usable = append(usable, usableObs{o, i})
	}
	if len(usable) < 3 {
		return nil, nil, "", errors.New("insufficient stations for solve")
	}

	// Reference = lex-smallest station with usable timestamp.
	names := make([]string, 0, len(usable))
	for _, u := range usable {
		names = append(names, u.o.Station)
	}
	sort.Strings(names)
	refStation := names[0]

	var pairKeysUsed []string
	mlatObs := make([]MlatObservation, 0, len(usable))
	for _, u := range usable {
		o := u.o
		lockTNs := o.PreambleLockTNs
		cls := TimestampSoftwareLock
		switch {
		case lockTNs == 0:
			lockTNs = o.StationTNs
			cls = TimestampFrame
		case o.Station == refStation:
			cls = TimestampSync // reference always treated as sync if it participates
		default:
			pk := PairKey(o.Station, refStation)
			snap, ok, err := store.LatestPairSnapshotAtOrBefore(eventTimeNs, pk)
			if err != nil {
				return nil, nil, "", fmt.Errorf("pair snapshot lookup %s: %w", pk, err)
			}
			// Apply the snapshot only when it was converged AND was still
			// fresh at the target event time. Without the freshness gate
			// an old converged snapshot would silently label the replay
			// as sync class using offsets that should have aged out --
			// pairStatusNow does this gating in the live path, so honour
			// the same MaxAgeS bound here.
			fresh := false
			if ok {
				ageNs := int64(eventTimeNs) - int64(snap.SnapshotTimeNs)
				maxAgeNs := int64(snap.MaxAgeS * float64(time.Second))
				if ageNs >= 0 && ageNs <= maxAgeNs {
					fresh = true
				}
			}
			if ok && snap.StatusAtSnapshot == "converged" && fresh {
				// Mirror clocksync.CorrectAndClassify: pair median is
				// signed as (B.PreambleLockTNs - A.PreambleLockTNs)
				// where A < B lex. Rebase obs onto refStation:
				//   obs on A-side, ref=B  -> ADD median
				//   obs on B-side, ref=A  -> SUBTRACT median
				pkA, _, _ := pairKeyEndpoints(pk)
				corrected := int64(lockTNs)
				if o.Station == pkA {
					corrected += int64(snap.MedianNs)
				} else {
					corrected -= int64(snap.MedianNs)
				}
				if corrected < 0 {
					corrected = 0
				}
				lockTNs = uint64(corrected)
				cls = TimestampSync
				pairKeysUsed = append(pairKeysUsed, pk)
			}
			// If no converged-and-fresh snapshot at event time, fall back
			// to raw software_lock (no correction). The result's
			// WorstTimestampCls will surface the degradation honestly.
		}
		mlatObs = append(mlatObs, MlatObservation{
			StationName:         o.Station,
			Lat:                 o.StationLat,
			Lon:                 o.StationLon,
			AltM:                o.StationAltM,
			TNs:                 o.StationTNs,
			LockTNs:             lockTNs,
			TAccNs:              o.StationTAccNs,
			PrecomputedClass:    cls,
			HasPrecomputedClass: true,
		})
	}

	res, err := Solve(mlatObs)
	if err != nil {
		return nil, nil, "", fmt.Errorf("solve: %w", err)
	}
	return res, pairKeysUsed, refStation, nil
}

// replayEvent is the on-wire shape of REPLAY_GEOLOCATED. Distinct from
// the live GEOLOCATED so dashboard / export consumers can keyhole on
// event type. clock_model_time_ns is the timestamp of the pair-offset
// state used; for event_time mode it equals event_time_ns; for
// current_model mode it equals the wall-clock time the resolve ran.
// `advisory`, when present, is a human-readable warning attached to
// experimental modes so a casual consumer who skips the replay_mode
// field still sees the caveat.
type replayEvent struct {
	Event                string   `json:"event"`
	SourceEventID        string   `json:"source_event_id"`
	ReplayMode           string   `json:"replay_mode"`
	ClockModelTimeNs     uint64   `json:"clock_model_time_ns"`
	Advisory             string   `json:"advisory,omitempty"`
	From                 string   `json:"from"`
	PacketID             uint32   `json:"packet_id"`
	EmissionSeq          int      `json:"emission_seq,omitempty"`
	Lat                  float64  `json:"lat"`
	Lon                  float64  `json:"lon"`
	UncertaintyM         float64  `json:"uncertainty_m"`
	StationCount         int      `json:"station_count"`
	Iterations           int      `json:"iterations"`
	TimestampClass       string   `json:"timestamp_class"`
	Degraded             bool     `json:"timestamp_class_degraded,omitempty"`
	ClockSyncReference   string   `json:"clock_sync_reference,omitempty"`
	PairSnapshotKeysUsed []string `json:"pair_snapshot_keys_used,omitempty"`
}

// resolveWithCurrentModel re-runs the solver against TODAY's clock
// model, applied to the historical observations. Useful for asking
// "what would my current calibration say about this old event?" but
// dangerous as an operator default -- the live offsets reflect today's
// pair-state, not the offsets that were valid when this event actually
// happened. The UI gates this behind an Advanced disclosure and the
// SSE event carries an advisory field so consumers can't accidentally
// treat the result as a clean replay.
func resolveWithCurrentModel(cs *ClockSync, rec *ClusterObservationRecord) (
	*MlatResult, []string, string, error,
) {
	if rec == nil {
		return nil, nil, "", errors.New("nil record")
	}
	if cs == nil {
		return nil, nil, "", errors.New("clock-sync not running")
	}
	type usableObs struct {
		o ClusterObservationStation
	}
	var usable []usableObs
	for _, o := range rec.Observations {
		if o.StationTNs == 0 || o.StationLat == 0 || o.StationLon == 0 {
			continue
		}
		if o.StationTAccNs > 100_000_000 {
			continue
		}
		usable = append(usable, usableObs{o})
	}
	if len(usable) < 3 {
		return nil, nil, "", errors.New("insufficient stations for solve")
	}

	refStation := cs.PickReferenceStation()
	// Fallback when clock-sync has no converged pairs yet: use the
	// lex-smallest station name as a deterministic stand-in. The
	// resulting solve gets degraded class but at least runs.
	if refStation == "" {
		names := make([]string, 0, len(usable))
		for _, u := range usable {
			names = append(names, u.o.Station)
		}
		sort.Strings(names)
		refStation = names[0]
	}

	var pairKeysUsed []string
	mlatObs := make([]MlatObservation, 0, len(usable))
	for _, u := range usable {
		o := u.o
		obs := Observation{
			Station: o.Station, StationLat: o.StationLat, StationLon: o.StationLon,
			StationAltM:     o.StationAltM,
			StationTNs:      o.StationTNs,
			StationTAccNs:   o.StationTAccNs,
			PreambleLockTNs: o.PreambleLockTNs,
			SnrDB:           o.SnrDB,
			RssiDB:          o.RssiDB,
		}
		lockTNs, cls := cs.CorrectAndClassify(obs, refStation)
		if cls == TimestampSync && o.Station != refStation {
			pairKeysUsed = append(pairKeysUsed, PairKey(o.Station, refStation))
		}
		mlatObs = append(mlatObs, MlatObservation{
			StationName:         o.Station,
			Lat:                 o.StationLat,
			Lon:                 o.StationLon,
			AltM:                o.StationAltM,
			TNs:                 o.StationTNs,
			LockTNs:             lockTNs,
			TAccNs:              o.StationTAccNs,
			PrecomputedClass:    cls,
			HasPrecomputedClass: true,
		})
	}

	res, err := Solve(mlatObs)
	if err != nil {
		return nil, nil, "", fmt.Errorf("solve: %w", err)
	}
	return res, pairKeysUsed, refStation, nil
}

// resolveHandler is the POST /api/resolve handler factory. Captures
// store + hub so they can be wired once at startup. Returns 400 for bad
// input, 404 when the event is not in the cluster_observations bucket,
// 422 when the solver couldn't run, 503 when persistence is off.
func resolveHandler(store *EventStore, hub *SSEHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			jsonError(w, "--state-db required for replay", http.StatusServiceUnavailable)
			return
		}
		if hub == nil {
			jsonError(w, "SSE hub not running", http.StatusServiceUnavailable)
			return
		}
		var req ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Mode == "" {
			req.Mode = "event_time"
		}
		if req.Mode != "event_time" && req.Mode != "current_model" {
			jsonError(w,
				"mode must be 'event_time' or 'current_model'",
				http.StatusBadRequest)
			return
		}
		if req.From == "" || req.PacketID == 0 || req.EventTimeNs == 0 {
			jsonError(w, "missing from / packet_id / event_time_ns", http.StatusBadRequest)
			return
		}

		rec, err := findClusterObservation(store, req.EventTimeNs, req.From, req.PacketID, req.EmissionSeq)
		if err != nil {
			jsonError(w, fmt.Sprintf("cluster lookup: %v", err), http.StatusInternalServerError)
			return
		}
		if rec == nil {
			jsonError(w, "event not found in cluster_observations", http.StatusNotFound)
			return
		}

		var (
			res              *MlatResult
			pairKeysUsed     []string
			refStation       string
			clockModelTimeNs uint64
			advisory         string
		)
		switch req.Mode {
		case "event_time":
			res, pairKeysUsed, refStation, err = resolveAtEventTime(store, rec)
			clockModelTimeNs = req.EventTimeNs
		case "current_model":
			res, pairKeysUsed, refStation, err = resolveWithCurrentModel(globalClockSync, rec)
			clockModelTimeNs = uint64(time.Now().UnixNano())
			advisory = "Today's clock model applied to historical observations. " +
				"This is NOT a clean replay; offsets reflect current state, not " +
				"the offsets that were valid at event_time_ns. Use with caution."
		}
		if err != nil {
			jsonError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		ev := replayEvent{
			Event:                "REPLAY_GEOLOCATED",
			SourceEventID:        req.eventID(),
			ReplayMode:           req.Mode,
			ClockModelTimeNs:     clockModelTimeNs,
			Advisory:             advisory,
			From:                 req.From,
			PacketID:             req.PacketID,
			EmissionSeq:          req.EmissionSeq,
			Lat:                  res.Lat,
			Lon:                  res.Lon,
			UncertaintyM:         res.UncertaintyM,
			StationCount:         res.StationCount,
			Iterations:           res.Iterations,
			TimestampClass:       res.WorstTimestampCls.String(),
			Degraded:             res.Degraded,
			ClockSyncReference:   refStation,
			PairSnapshotKeysUsed: pairKeysUsed,
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			jsonError(w, "marshal error", http.StatusInternalServerError)
			return
		}
		hub.Publish(payload)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"queued":          true,
			"source_event_id": req.eventID(),
		})
	}
}
