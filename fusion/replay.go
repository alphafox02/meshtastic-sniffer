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
	"strings"
)

// ResolveRequest is the POST /api/resolve wire format. Fields mirror
// the timeline-row keys the Evidence tab already has, so the UI button
// just forwards what it already knows.
type ResolveRequest struct {
	From        string `json:"from"`
	PacketID    uint32 `json:"packet_id"`
	EmissionSeq int    `json:"emission_seq,omitempty"`
	EventTimeNs uint64 `json:"event_time_ns"`
	Mode        string `json:"mode,omitempty"` // "event_time" (default) | "current_model" (deferred)
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
			if ok && snap.StatusAtSnapshot == "converged" {
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
			// If no converged snapshot at event time, fall back to raw
			// software_lock (no correction). The result's WorstTimestampCls
			// will surface the degradation honestly.
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
// state used; for event_time mode it equals event_time_ns.
type replayEvent struct {
	Event                string   `json:"event"`
	SourceEventID        string   `json:"source_event_id"`
	ReplayMode           string   `json:"replay_mode"`
	ClockModelTimeNs     uint64   `json:"clock_model_time_ns"`
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
		if req.Mode != "event_time" {
			// current_model lands in a separate commit; reject here so
			// older clients can't accidentally trigger an experimental
			// replay path that the backend hasn't shipped yet.
			jsonError(w,
				"mode must be 'event_time' (current_model replay not yet supported)",
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

		res, pairKeysUsed, refStation, err := resolveAtEventTime(store, rec)
		if err != nil {
			jsonError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		ev := replayEvent{
			Event:                "REPLAY_GEOLOCATED",
			SourceEventID:        req.eventID(),
			ReplayMode:           req.Mode,
			ClockModelTimeNs:     req.EventTimeNs,
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
