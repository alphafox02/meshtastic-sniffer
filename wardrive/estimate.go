// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/estimate.go: emitter location estimation from RSSI-tagged
// GPS observations.
//
// The honest framing baked into both the algorithm and the README:
//
//	A single drive-past gives a centroid biased toward the road. The
//	estimate is correct iff the operator drove a closed loop around
//	the actual emitter location. Otherwise the centroid lies somewhere
//	on the road segment where signal was strongest, which can be
//	hundreds of meters off the true position. We compute and emit a
//	1-sigma "spread" radius, but it is *not* a guarantee that the
//	emitter sits within it -- it is a measure of consistency with the
//	data we have.
//
// v1 supports two estimator methods:
//
//   "self-reported"
//     If any decrypted POSITION packet exists for the node, trust its
//     coordinates. Mark the source explicitly so a viewer can tell
//     "the node told us where it was" from "we triangulated".
//
//   "rssi2-weighted-centroid"
//     The wardriving canonical baseline (Han et al., PAM 2009). Convert
//     each RSSI(dBm) to a linear power weight w_i = 10^(RSSI_i/10), then
//     weight by w_i^2. The centroid concentrates near where the
//     strongest hits were heard.
//
// Path-loss inversion is a v2 candidate; not implemented here.

package main

import (
	"math"
)

// EarthRadiusM is the mean Earth radius used for tiny-angle great-
// circle calculations. We use the spherical approximation (not WGS84)
// because the uncertainty floor (50 m) dominates any ellipsoidal
// correction at suburban driving scales.
const EarthRadiusM = 6_371_000.0

// uncertaintyFloorM is the minimum 1-sigma we ever report. Reflects
// honest GPS noise + the fundamental limit of "drove past once".
// Even with perfect data we shouldn't claim sub-50 m precision from
// RSSI on an omnidirectional antenna.
const uncertaintyFloorM = 50.0

// EstimateLocation computes a NodeAggregate's EstLat / EstLon /
// EstUncertaintyM / EstMethod from its observations. Mutates the
// aggregate in place. Returns false if there's no usable input
// (zero observations or no GPS-tagged ones).
//
// Pre-condition: agg.SelfReportedLat/Lon are already populated from
// any decrypted POSITION packets (the aggregator does that pass
// independently); when present, they short-circuit the centroid.
func EstimateLocation(agg *NodeAggregate, obs []Observation) bool {
	if agg == nil {
		return false
	}
	// Self-reported wins when present. Operators can fuzz / lie /
	// disable, so this is "best single estimate" not "ground truth".
	if agg.SelfReportedLat != 0 || agg.SelfReportedLon != 0 {
		agg.EstLat = agg.SelfReportedLat
		agg.EstLon = agg.SelfReportedLon
		agg.EstUncertaintyM = uncertaintyFloorM
		agg.EstMethod = "self-reported"
		return true
	}

	// Filter to observations with a real GPS fix. Pre-fix events
	// (rx_lat/lon both zero, or NaN from a bad gpsd parse) drop here.
	usable := make([]Observation, 0, len(obs))
	for _, o := range obs {
		if o.RxLat == 0 && o.RxLon == 0 {
			continue
		}
		if math.IsNaN(o.RxLat) || math.IsNaN(o.RxLon) {
			continue
		}
		usable = append(usable, o)
	}
	if len(usable) == 0 {
		return false
	}

	// Compute weights: w_i = 10^(RSSI/10), then square per Han et al.
	// Convert in linear-power space (mW). Negative dBm yields a tiny
	// fraction; squaring sharpens the falloff so the strongest hits
	// dominate.
	type weighted struct {
		lat, lon, w float64
	}
	wts := make([]weighted, len(usable))
	var sumW float64
	for i, o := range usable {
		linear := math.Pow(10, o.RSSIdBm/10.0)
		w := linear * linear
		wts[i] = weighted{lat: o.RxLat, lon: o.RxLon, w: w}
		sumW += w
	}
	if sumW <= 0 {
		// Degenerate: all observations had RSSI = -inf or similar.
		// Fall back to an unweighted mean so we still produce a fix
		// rather than NaN out.
		for i := range wts {
			wts[i].w = 1.0
		}
		sumW = float64(len(wts))
	}

	var lat, lon float64
	for _, w := range wts {
		lat += w.lat * w.w
		lon += w.lon * w.w
	}
	lat /= sumW
	lon /= sumW

	// 1-sigma = RSSI^2-weighted standard distance from the centroid,
	// converted from radians-of-great-circle to meters. Floored so
	// small samples don't claim implausible precision.
	var sumWD2 float64
	for _, w := range wts {
		d := haversineMeters(lat, lon, w.lat, w.lon)
		sumWD2 += w.w * d * d
	}
	sigma := math.Sqrt(sumWD2 / sumW)
	if sigma < uncertaintyFloorM {
		sigma = uncertaintyFloorM
	}

	agg.EstLat = lat
	agg.EstLon = lon
	agg.EstUncertaintyM = sigma
	agg.EstMethod = "rssi2-weighted-centroid"
	return true
}

// haversineMeters computes great-circle distance in meters between
// two lat/lon points (degrees). Sufficient for the few-km scales
// involved in wardriving; ellipsoidal correction is below the
// uncertainty floor at this range.
func haversineMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const degToRad = math.Pi / 180.0
	dLat := (lat2 - lat1) * degToRad
	dLon := (lon2 - lon1) * degToRad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*degToRad)*math.Cos(lat2*degToRad)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return EarthRadiusM * c
}
