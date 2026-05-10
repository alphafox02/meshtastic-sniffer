// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/aggregate.go: collapse per-frame Observations into per-node
// NodeAggregate rows. Plain functions, no DB; the SQLite read path is
// expected to deliver a slice of Observations to this code.

package main

import "time"

// Aggregate groups observations by NodeID and produces one
// NodeAggregate per unique node. Each aggregate has:
//   - first/last seen, observation count
//   - best RSSI + the timestamp/SNR at that moment
//   - latched LongName/ShortName/HWModel/Role from any NODEINFO packets
//   - self-reported lat/lon from any POSITION packets (most-recent wins)
//   - EstLat/EstLon/EstUncertaintyM/EstMethod via EstimateLocation()
//
// Latching strategy: NODEINFO and POSITION fields are *latched*, so a
// single decrypt during the session is enough to label a node forever.
// Subsequent observations don't unset them. This is what an operator
// expects: "I saw it called Foo once; keep calling it Foo."
func Aggregate(obs []Observation, sessionID, stationID string) []*NodeAggregate {
	byID := map[string]*NodeAggregate{}
	byObs := map[string][]Observation{}

	for _, o := range obs {
		if o.NodeID == "" {
			continue
		}
		agg, ok := byID[o.NodeID]
		if !ok {
			agg = &NodeAggregate{
				NodeID:      o.NodeID,
				ChannelHash: o.ChannelHash,
				FirstSeen:   o.TS,
				LastSeen:    o.TS,
				BestRSSIdBm: o.RSSIdBm,
				BestRSSITS:  o.TS,
				BestSNRdB:   o.SNRdB,
				SessionID:   sessionID,
				StationID:   stationID,
			}
			byID[o.NodeID] = agg
		}
		// Time bounds.
		if o.TS.Before(agg.FirstSeen) {
			agg.FirstSeen = o.TS
		}
		if o.TS.After(agg.LastSeen) {
			agg.LastSeen = o.TS
		}
		// Strongest hit so far. Initial value is the first observation's
		// RSSI, so any later equal-or-stronger reading wins; stable on ties.
		if o.RSSIdBm > agg.BestRSSIdBm || agg.ObsCount == 0 {
			agg.BestRSSIdBm = o.RSSIdBm
			agg.BestRSSITS = o.TS
			agg.BestSNRdB = o.SNRdB
		}
		// Latch metadata from any NODEINFO decrypt.
		if o.LongName != "" && agg.LongName == "" {
			agg.LongName = o.LongName
		}
		if o.ShortName != "" && agg.ShortName == "" {
			agg.ShortName = o.ShortName
		}
		if o.HWModel != 0 && agg.HWModel == 0 {
			agg.HWModel = o.HWModel
		}
		if o.Role != 0 && agg.Role == 0 {
			agg.Role = o.Role
		}
		// Latch channel name from any successful decrypt; slot RF
		// metadata too, since those are constant per (channel_hash,
		// preset) pair.
		if o.ChannelName != "" && agg.ChannelName == "" {
			agg.ChannelName = o.ChannelName
		}
		if o.Preset != "" && agg.Preset == "" {
			agg.Preset = o.Preset
		}
		if o.BWHz != 0 && agg.BWHz == 0 {
			agg.BWHz = o.BWHz
		}
		if o.FreqHz != 0 && agg.FreqHz == 0 {
			agg.FreqHz = o.FreqHz
		}
		// Self-reported position: most-recent wins (the node may move).
		if o.SelfReportedLat != 0 || o.SelfReportedLon != 0 {
			ts := o.TS
			if agg.SelfReportedTS == nil || ts.After(*agg.SelfReportedTS) {
				agg.SelfReportedLat = o.SelfReportedLat
				agg.SelfReportedLon = o.SelfReportedLon
				agg.SelfReportedAltM = o.SelfReportedAltM
				agg.SelfReportedTS = &ts
			}
		}
		agg.ObsCount++
		byObs[o.NodeID] = append(byObs[o.NodeID], o)
	}

	// Run the estimator on each node.
	out := make([]*NodeAggregate, 0, len(byID))
	for id, agg := range byID {
		EstimateLocation(agg, byObs[id])
		out = append(out, agg)
	}
	// Sort deterministically by NodeID so exports are reproducible
	// across runs (helpful for tests + diffing CSVs by hand).
	sortByNodeID(out)
	return out
}

func sortByNodeID(a []*NodeAggregate) {
	// Tiny manual insertion sort -- avoids pulling sort.Slice for a
	// 4-line dependency, and N is always small (one drive ~ <500 nodes).
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1].NodeID > a[j].NodeID; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// SessionWindow computes a session's start/end timestamps from
// observations, used to fill Session.StartTS / EndTS when the
// caller doesn't track them externally.
func SessionWindow(obs []Observation) (start, end time.Time) {
	for i, o := range obs {
		if i == 0 {
			start, end = o.TS, o.TS
			continue
		}
		if o.TS.Before(start) {
			start = o.TS
		}
		if o.TS.After(end) {
			end = o.TS
		}
	}
	return
}
