// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"math"
	"testing"
	"time"
)

func TestEstimate_SelfReportedShortCircuits(t *testing.T) {
	agg := &NodeAggregate{
		NodeID:          "!aaaa",
		SelfReportedLat: 47.610,
		SelfReportedLon: -122.333,
	}
	if !EstimateLocation(agg, nil) {
		t.Fatalf("EstimateLocation returned false on self-reported")
	}
	if agg.EstMethod != "self-reported" {
		t.Errorf("method=%q want self-reported", agg.EstMethod)
	}
	if agg.EstLat != 47.610 || agg.EstLon != -122.333 {
		t.Errorf("est=(%v,%v) want (47.610,-122.333)", agg.EstLat, agg.EstLon)
	}
	if agg.EstUncertaintyM < uncertaintyFloorM {
		t.Errorf("uncertainty=%v should be >= %v", agg.EstUncertaintyM, uncertaintyFloorM)
	}
}

func TestEstimate_CentroidConvergesNearTruth(t *testing.T) {
	// Drive a tight loop around (47.610, -122.333). RSSI follows
	// log-distance path-loss with the strongest hits at closest range.
	const trueLat, trueLon = 47.6105, -122.3325
	t0 := time.Now().UTC()
	obs := []Observation{}
	for i := 0; i < 60; i++ {
		theta := 2 * math.Pi * float64(i) / 60.0
		rxLat := 47.610 + 0.0008*math.Sin(theta)
		rxLon := -122.333 + 0.0008*math.Cos(theta)
		d := haversineMeters(rxLat, rxLon, trueLat, trueLon)
		if d < 5 {
			d = 5
		}
		rssi := 22.0 - 40.0 - 10*2.5*math.Log10(d)
		obs = append(obs, Observation{
			TS: t0.Add(time.Duration(i) * time.Second),
			NodeID: "!bbbb", RxLat: rxLat, RxLon: rxLon, RSSIdBm: rssi,
		})
	}
	agg := &NodeAggregate{NodeID: "!bbbb"}
	if !EstimateLocation(agg, obs) {
		t.Fatalf("EstimateLocation returned false")
	}
	if agg.EstMethod != "rssi2-weighted-centroid" {
		t.Errorf("method=%q want rssi2-weighted-centroid", agg.EstMethod)
	}
	dist := haversineMeters(agg.EstLat, agg.EstLon, trueLat, trueLon)
	if dist > 50 {
		t.Errorf("centroid is %.1f m from truth; expected < 50 m", dist)
	}
	if agg.EstUncertaintyM < uncertaintyFloorM {
		t.Errorf("uncertainty=%v below floor %v", agg.EstUncertaintyM, uncertaintyFloorM)
	}
}

func TestEstimate_NoUsableObservationsReturnsFalse(t *testing.T) {
	agg := &NodeAggregate{NodeID: "!cccc"}
	// All observations have rx_lat/lon == 0 (pre-fix); should bail.
	obs := []Observation{
		{NodeID: "!cccc", RSSIdBm: -80},
		{NodeID: "!cccc", RSSIdBm: -85},
	}
	if EstimateLocation(agg, obs) {
		t.Fatalf("EstimateLocation returned true on no-fix data")
	}
}

func TestHaversine_KnownDistance(t *testing.T) {
	// Approx 1 km north-south at lat=0: 0.00899 deg of latitude.
	// Roughly verify haversine produces the right scale.
	d := haversineMeters(0, 0, 0.00899, 0)
	if d < 990 || d > 1010 {
		t.Errorf("haversine(0,0,0.00899,0) = %.1f m; want ~1000", d)
	}
}
