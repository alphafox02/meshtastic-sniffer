// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// edge_test.go: pathological inputs the synthetic fixture doesn't
// exercise. If any of these panic or produce garbage, the binary
// would do the same on a real captured dataset with missing GPS
// fixes, single-frame nodes, or other real-world degeneracy.

package main

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func TestAggregate_EmptyObservations(t *testing.T) {
	aggs := Aggregate(nil, "s", "rx")
	if len(aggs) != 0 {
		t.Fatalf("empty obs returned %d aggregates; want 0", len(aggs))
	}
}

func TestAggregate_ObservationsWithEmptyNodeID(t *testing.T) {
	obs := []Observation{
		{NodeID: "", RSSIdBm: -80, RxLat: 47.6, RxLon: -122.3, TS: time.Now()},
		{NodeID: "!aaaa", RSSIdBm: -75, RxLat: 47.6, RxLon: -122.3, TS: time.Now()},
	}
	aggs := Aggregate(obs, "s", "rx")
	if len(aggs) != 1 {
		t.Fatalf("got %d aggregates; want 1 (empty NodeID rows must be skipped)", len(aggs))
	}
	if aggs[0].NodeID != "!aaaa" {
		t.Errorf("kept wrong node: %q", aggs[0].NodeID)
	}
}

func TestAggregate_SingleObservationPerNode(t *testing.T) {
	t0 := time.Now()
	obs := []Observation{
		{NodeID: "!a", RSSIdBm: -70, RxLat: 47.6, RxLon: -122.3, TS: t0},
		{NodeID: "!b", RSSIdBm: -85, RxLat: 47.61, RxLon: -122.31, TS: t0},
	}
	aggs := Aggregate(obs, "s", "rx")
	if len(aggs) != 2 {
		t.Fatalf("got %d aggregates; want 2", len(aggs))
	}
	for _, a := range aggs {
		if a.ObsCount != 1 {
			t.Errorf("%s: obs_count=%d want 1", a.NodeID, a.ObsCount)
		}
		// Single observation should still produce a fix at the
		// operator's location, at the uncertainty floor.
		if a.EstMethod != "rssi2-weighted-centroid" {
			t.Errorf("%s: method=%q", a.NodeID, a.EstMethod)
		}
		if a.EstUncertaintyM != uncertaintyFloorM {
			t.Errorf("%s: 1-sigma=%v want floor %v", a.NodeID, a.EstUncertaintyM, uncertaintyFloorM)
		}
	}
}

func TestEstimate_AllRSSIZero(t *testing.T) {
	// Degenerate: every observation has RSSI = 0 dBm (extremely strong;
	// unusual but possible near a transmitter). Weights are equal,
	// fall back to simple mean.
	obs := []Observation{
		{NodeID: "!x", RxLat: 47.610, RxLon: -122.331, RSSIdBm: 0},
		{NodeID: "!x", RxLat: 47.612, RxLon: -122.333, RSSIdBm: 0},
	}
	agg := &NodeAggregate{NodeID: "!x"}
	if !EstimateLocation(agg, obs) {
		t.Fatalf("expected true with non-empty obs")
	}
	wantLat := (47.610 + 47.612) / 2
	wantLon := (-122.331 - 122.333) / 2
	if math.Abs(agg.EstLat-wantLat) > 1e-6 || math.Abs(agg.EstLon-wantLon) > 1e-6 {
		t.Errorf("est=(%v,%v) want (%v,%v)", agg.EstLat, agg.EstLon, wantLat, wantLon)
	}
}

func TestEstimate_NaNFixIgnored(t *testing.T) {
	obs := []Observation{
		{NodeID: "!x", RxLat: math.NaN(), RxLon: -122.3, RSSIdBm: -70},
		{NodeID: "!x", RxLat: 47.6, RxLon: math.NaN(), RSSIdBm: -70},
		{NodeID: "!x", RxLat: 47.6, RxLon: -122.3, RSSIdBm: -70},
	}
	agg := &NodeAggregate{NodeID: "!x"}
	if !EstimateLocation(agg, obs) {
		t.Fatalf("expected true with one usable obs")
	}
	if math.IsNaN(agg.EstLat) || math.IsNaN(agg.EstLon) {
		t.Errorf("NaN leaked into estimate: lat=%v lon=%v", agg.EstLat, agg.EstLon)
	}
	// One usable observation at (47.6, -122.3); centroid math goes
	// through w*lat / w so the result lands within float-ulps of the
	// input, not exactly equal. Tolerate sub-meter drift.
	if math.Abs(agg.EstLat-47.6) > 1e-9 || math.Abs(agg.EstLon-(-122.3)) > 1e-9 {
		t.Errorf("est=(%v,%v) want ~(47.6,-122.3) -- NaN observations should be skipped",
			agg.EstLat, agg.EstLon)
	}
}

func TestEstimate_SelfReportedWinsEvenWithObservations(t *testing.T) {
	// Self-reported position should short-circuit centroid even when
	// there are many GPS-tagged observations -- the broadcast is the
	// best estimate we have.
	obs := []Observation{}
	for i := 0; i < 50; i++ {
		obs = append(obs, Observation{
			NodeID: "!x", RxLat: 47.61, RxLon: -122.33, RSSIdBm: -60,
		})
	}
	agg := &NodeAggregate{
		NodeID:          "!x",
		SelfReportedLat: 47.7,
		SelfReportedLon: -122.4,
	}
	EstimateLocation(agg, obs)
	if agg.EstMethod != "self-reported" {
		t.Errorf("method=%q want self-reported", agg.EstMethod)
	}
	if agg.EstLat != 47.7 || agg.EstLon != -122.4 {
		t.Errorf("est=(%v,%v) want (47.7,-122.4)", agg.EstLat, agg.EstLon)
	}
}

func TestWriteAggregatedCSV_EmptyNodeListProducesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAggregatedCSV(&buf, Session{AppRelease: "x"}, nil); err != nil {
		t.Fatalf("WriteAggregatedCSV: %v", err)
	}
	out := buf.String()
	// preamble + header + nothing
	lines := bytes.Count([]byte(out), []byte("\n"))
	if lines != 2 {
		t.Errorf("got %d lines (preamble + header), got %d -- want 2", lines, lines)
	}
}

func TestWriteKML_EmptyInputDoesntPanic(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteKML(&buf, Session{AppRelease: "x"}, nil, nil); err != nil {
		t.Fatalf("WriteKML on empty input: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatalf("empty output")
	}
}

func TestAggregate_LatchingDoesNotOverwrite(t *testing.T) {
	// The first NODEINFO sets long_name; a subsequent one with a
	// different value should NOT overwrite (latching semantics:
	// "I saw it called Foo once; keep calling it Foo").
	t0 := time.Now()
	obs := []Observation{
		{NodeID: "!x", LongName: "First", RxLat: 47.6, RxLon: -122.3, RSSIdBm: -70, TS: t0},
		{NodeID: "!x", LongName: "Second", RxLat: 47.6, RxLon: -122.3, RSSIdBm: -70, TS: t0.Add(time.Second)},
	}
	aggs := Aggregate(obs, "s", "rx")
	if aggs[0].LongName != "First" {
		t.Errorf("latch broken: long_name=%q want %q", aggs[0].LongName, "First")
	}
}

func TestEstimate_ConvergesBetterWithMoreObservations(t *testing.T) {
	// Sanity check: a centroid estimated from 200 observations
	// should be no worse than one estimated from 20 (both surrounding
	// the same truth). Guards against any future regression in
	// the weighting math that would degrade with more data.
	const trueLat, trueLon = 47.6105, -122.3325
	mkObs := func(n int) []Observation {
		obs := make([]Observation, n)
		for i := 0; i < n; i++ {
			theta := 2 * math.Pi * float64(i) / float64(n)
			rxLat := trueLat + 0.001*math.Sin(theta)
			rxLon := trueLon + 0.001*math.Cos(theta)
			d := haversineMeters(rxLat, rxLon, trueLat, trueLon)
			rssi := 22.0 - 40.0 - 10*2.5*math.Log10(d)
			obs[i] = Observation{
				NodeID: "!x", RxLat: rxLat, RxLon: rxLon, RSSIdBm: rssi,
			}
		}
		return obs
	}
	a20, a200 := &NodeAggregate{}, &NodeAggregate{}
	EstimateLocation(a20, mkObs(20))
	EstimateLocation(a200, mkObs(200))
	d20 := haversineMeters(a20.EstLat, a20.EstLon, trueLat, trueLon)
	d200 := haversineMeters(a200.EstLat, a200.EstLon, trueLat, trueLon)
	if d200 > d20+5 { // tolerance: small-N can occasionally win by luck of phase
		t.Errorf("more-obs estimate is worse: 20obs=%.1fm, 200obs=%.1fm", d20, d200)
	}
}

// Stress: 100 nodes x 100 observations each = 10k rows. Aggregation +
// export should be milliseconds, not seconds.
func TestStress_LargeFixture(t *testing.T) {
	t0 := time.Now()
	obs := make([]Observation, 0, 10000)
	for n := 0; n < 100; n++ {
		nodeID := "!" + nodeIDHex(n)
		nodeLat := 47.610 + float64(n)*0.0001
		nodeLon := -122.333 + float64(n)*0.0001
		for k := 0; k < 100; k++ {
			theta := 2 * math.Pi * float64(k) / 100.0
			rxLat := nodeLat + 0.0008*math.Sin(theta)
			rxLon := nodeLon + 0.0008*math.Cos(theta)
			d := haversineMeters(rxLat, rxLon, nodeLat, nodeLon)
			if d < 5 {
				d = 5
			}
			rssi := 22.0 - 40.0 - 10*2.5*math.Log10(d)
			obs = append(obs, Observation{
				NodeID:  nodeID,
				RxLat:   rxLat,
				RxLon:   rxLon,
				RSSIdBm: rssi,
				TS:      t0.Add(time.Duration(k) * time.Second),
			})
		}
	}
	start := time.Now()
	aggs := Aggregate(obs, "stress", "rx")
	aggDur := time.Since(start)

	if len(aggs) != 100 {
		t.Fatalf("got %d aggregates want 100", len(aggs))
	}
	if aggDur > 200*time.Millisecond {
		t.Errorf("aggregate too slow on 10k obs: %v -- target < 200ms", aggDur)
	}

	var buf bytes.Buffer
	start = time.Now()
	if err := WriteAggregatedCSV(&buf, Session{AppRelease: "x"}, aggs); err != nil {
		t.Fatalf("WriteAggregatedCSV: %v", err)
	}
	csvDur := time.Since(start)
	if csvDur > 50*time.Millisecond {
		t.Errorf("aggregated CSV too slow: %v -- target < 50ms", csvDur)
	}
	t.Logf("stress: 10k obs -> aggregate=%v csv=%v output=%d bytes",
		aggDur, csvDur, buf.Len())
}

func nodeIDHex(n int) string {
	const hex = "0123456789abcdef"
	out := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for i := 7; i >= 0; i-- {
		out[i] = hex[n&0xF]
		n >>= 4
	}
	return string(out)
}
