// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/mlat.go: hyperbolic-TDOA multilateration solver.
//
// Given N >= 3 observations of the same (from, packet_id) at known
// station positions and timestamps, estimate the emitter's lat/lon by
// iteratively minimizing the squared TDOA residuals.
//
// Reference:
//   Foy, "Position-Location Solutions by Taylor-Series Estimation",
//   IEEE Trans. Aerospace and Electronic Systems, AES-12(2), 1976.
//
// Implementation notes:
//   - Stations and emitter are in a local ENU (East/North/Up) frame
//     anchored at the centroid of the participating stations. ENU is
//     locally Cartesian, so geodesic complications drop out for the
//     few-km baselines this solver targets. Output is converted back
//     to lat/lon via the inverse anchor projection.
//   - Each observation is weighted by 1 / station_t_acc_ns -- a GPSDO
//     station with 100 ns accuracy effectively dominates an NTP-class
//     station with 1 ms accuracy by 4 orders of magnitude.
//   - Convergence test: position change < 1 m or 20 iterations. The
//     algorithm is well-conditioned for stations spread around the
//     emitter; for collinear stations it converges to a hyperboloid
//     ambiguity which we report via uncertainty_m.
//
// Out-of-scope:
//   - Altitude is not estimated (assumed at sea level, z=0). 3D mlat
//     wants 4+ stations; we'll add it when ground-truth shows altitude
//     bias matters.
//   - The solver does not attempt to identify outliers. Bad timestamps
//     skew the result; a future improvement is RANSAC-style filtering.

package main

import (
	"errors"
	"math"
)

const speedOfLight = 299792458.0 // m/s

// mlatStation is the internal ENU+time+weight representation. Public
// API uses MlatObservation with lat/lon; Solve projects to mlatStation.
type mlatStation struct {
	x, y, z float64 // ENU meters from anchor
	t       float64 // seconds from common epoch
	w       float64 // weight = 1/sigma (where sigma = TAccNs)
}

// TimestampClass labels which sensor-side timestamp source the
// solver consumed for a given observation. Order is precision-best to
// precision-worst.
type TimestampClass uint8

const (
	TimestampSample       TimestampClass = iota // sample-derived TOA (best; tdoa-sample-epoch branch)
	TimestampSync                               // software_lock + converged clock-sync correction
	TimestampSoftwareLock                       // CLOCK_REALTIME at preamble-detect, no network correction
	TimestampFrame                              // CLOCK_REALTIME at frame-emit / dedup (worst)
)

func (c TimestampClass) String() string {
	switch c {
	case TimestampSample:
		return "sample"
	case TimestampSync:
		return "sync"
	case TimestampSoftwareLock:
		return "software_lock"
	case TimestampFrame:
		return "frame"
	}
	return "unknown"
}

// MlatObservation is one station's report of hearing a particular frame.
type MlatObservation struct {
	StationName  string
	Lat, Lon     float64 // station position
	AltM         float64
	TNs          uint64 // station_t_ns: frame-emit timestamp (worst tier)
	LockTNs      uint64 // preamble_lock_t_ns: preamble-detect timestamp (better)
	TAccNs       uint32 // station_t_acc_ns (clock-discipline class)
	// PrecomputedClass is the timestamp class the caller has already
	// resolved for this observation (e.g. via ClockSync.CorrectAndClassify).
	// When set to TimestampSample (the zero value) the solver falls back
	// to inferring the class from LockTNs/TNs presence -- preserves the
	// pre-clock-sync code paths that don't set this field. Set
	// explicitly to TimestampSync when clock-sync has corrected LockTNs
	// onto a converged network reference.
	PrecomputedClass TimestampClass
}

// resolveTNs picks the best available timestamp from an observation
// and returns the value plus its class. When PrecomputedClass is set
// (non-zero -- note that TimestampSample is the zero value and means
// "infer"), it wins. Otherwise we fall back to inferring from
// LockTNs/TNs presence: software_lock > frame.
func (o MlatObservation) resolveTNs() (uint64, TimestampClass) {
	if o.PrecomputedClass != TimestampSample {
		if o.LockTNs != 0 {
			return o.LockTNs, o.PrecomputedClass
		}
		return o.TNs, o.PrecomputedClass
	}
	if o.LockTNs != 0 {
		return o.LockTNs, TimestampSoftwareLock
	}
	return o.TNs, TimestampFrame
}

// MlatResult is the solver's emitter-position estimate.
type MlatResult struct {
	Lat, Lon          float64 // estimated emitter position
	UncertaintyM      float64 // 1-sigma residual in meters
	Iterations        int     // how many Newton iterations until convergence
	StationCount      int     // observations consumed
	TimestampClasses  map[TimestampClass]int // count of obs by timestamp source
	WorstTimestampCls TimestampClass         // weakest class consumed; uncertainty floor
	Degraded          bool                   // true when a mix of classes was used
	// Clock-sync diagnostics, populated by the fusion event loop after
	// solver returns. Surfaced on the GEOLOCATED JSON for operator UI.
	ClockSyncPairCount    int     // converged pairs touching contributing stations
	ClockSyncResidualNs   float64 // max MAD across contributing pairs
	ClockSyncAnchorCount  int     // distinct anchors that contributed to the converged pairs
	ClockSyncReference    string  // station chosen as the network time reference (or "")
}

// Solve runs hyperbolic-TDOA multilateration. Requires at least 3
// distinct station positions; fewer returns ErrInsufficient.
func Solve(obs []MlatObservation) (*MlatResult, error) {
	if len(obs) < 3 {
		return nil, ErrInsufficient
	}

	// Pick anchor = centroid for the local-ENU projection. Reduces
	// numerical conditioning issues vs. an arbitrary fixed anchor.
	var anchorLat, anchorLon float64
	for i := range obs {
		anchorLat += obs[i].Lat
		anchorLon += obs[i].Lon
	}
	anchorLat /= float64(len(obs))
	anchorLon /= float64(len(obs))

	// Resolve each observation's best-available timestamp + class.
	// LockTNs (software_lock) wins over TNs (frame) when present; the
	// "sample" class lands in a future branch and is not produced
	// here yet.
	resolved := make([]uint64, len(obs))
	classes := make([]TimestampClass, len(obs))
	classCounts := map[TimestampClass]int{}
	for i := range obs {
		resolved[i], classes[i] = obs[i].resolveTNs()
		classCounts[classes[i]]++
	}

	// Rebase TNs in uint64 space BEFORE converting to seconds. At
	// epoch-class magnitudes (~1.7e18 ns), float64 has only ~64 ns
	// of precision -- doing `TNs*1e-9` directly loses the nanosecond
	// LSBs we need for mlat. Subtracting a common epoch in uint64 first
	// keeps the resulting differences in a precision-safe range.
	minTNs := resolved[0]
	for i := range resolved {
		if resolved[i] < minTNs {
			minTNs = resolved[i]
		}
	}

	// Mixing timestamp classes across stations means the solver is
	// fed observations whose pipeline latencies disagree by tens of
	// milliseconds -- a "frame" obs in the same solve as a
	// "software_lock" obs poisons the result. Flag the solve as
	// degraded so the caller can mark/inflate uncertainty.
	worstClass := TimestampSample
	for _, c := range classes {
		if c > worstClass {
			worstClass = c
		}
	}
	degraded := len(classCounts) > 1

	// Project each station to ENU (meters from anchor).
	stations := make([]mlatStation, len(obs))
	for i := range obs {
		x, y := llToEnu(obs[i].Lat, obs[i].Lon, anchorLat, anchorLon)
		stations[i] = mlatStation{
			x: x, y: y, z: obs[i].AltM,
			t: float64(resolved[i]-minTNs) * 1e-9,
			w: 1.0 / float64(maxU32(obs[i].TAccNs, 1)),
		}
	}

	// Initial guess: try the station centroid first, but for 4+ stations
	// also attempt multi-start from each station's position and pick the
	// solution with smallest weighted residual. This breaks the classic
	// hyperbolic-ambiguity local minimum that Newton-Gauss can stick in.
	type startGuess struct{ x, y float64 }
	starts := []startGuess{{0, 0}} // centroid (anchor)
	for _, s := range stations {
		starts = append(starts, startGuess{s.x, s.y})
	}

	bestResidual := math.Inf(1)
	var bestPx, bestPy float64
	bestIter := 0

	for _, start := range starts {
		px, py := start.x, start.y
		const pz = 0.0 // sea-level constraint; estimating altitude wants 4+ stations and adds little for short-range mesh
		residual, iter, success := lmIterate(stations, &px, &py, pz)
		if success && residual < bestResidual {
			bestResidual = residual
			bestPx, bestPy = px, py
			bestIter = iter
		}
	}

	if bestResidual == math.Inf(1) {
		return nil, errors.New("mlat: failed to converge from any starting point")
	}
	residual := bestResidual
	px := bestPx
	py := bestPy
	iter := bestIter

	// Convert ENU back to lat/lon.
	emitterLat, emitterLon := enuToLl(px, py, anchorLat, anchorLon)

	// 1-sigma residual: sqrt(residual / DOF) -- degrees of freedom is
	// (N - 2) for a 2-unknown solve from N-1 equations.
	dof := len(stations) - 2
	if dof < 1 {
		dof = 1
	}
	uncertainty := math.Sqrt(residual / float64(dof))

	return &MlatResult{
		Lat:               emitterLat,
		Lon:               emitterLon,
		UncertaintyM:      uncertainty,
		Iterations:        iter,
		StationCount:      len(stations),
		TimestampClasses:  classCounts,
		WorstTimestampCls: worstClass,
		Degraded:          degraded,
	}, nil
}

// ErrInsufficient is returned by Solve when fewer than 3 observations
// are provided.
var ErrInsufficient = errors.New("mlat: need at least 3 observations")

// llToEnu projects (lat, lon) to (east-meters, north-meters) relative
// to (anchorLat, anchorLon) using the local-tangent-plane equirectangular
// approximation. Accurate to <1 m across baselines under ~50 km, which
// covers any realistic LoRa mesh.
func llToEnu(lat, lon, anchorLat, anchorLon float64) (east, north float64) {
	const earthR = 6371000.0
	dLat := (lat - anchorLat) * math.Pi / 180.0
	dLon := (lon - anchorLon) * math.Pi / 180.0
	north = earthR * dLat
	east = earthR * dLon * math.Cos(anchorLat*math.Pi/180.0)
	return
}

// enuToLl is the inverse of llToEnu.
func enuToLl(east, north, anchorLat, anchorLon float64) (lat, lon float64) {
	const earthR = 6371000.0
	lat = anchorLat + (north/earthR)*180.0/math.Pi
	lon = anchorLon + (east/(earthR*math.Cos(anchorLat*math.Pi/180.0)))*180.0/math.Pi
	return
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// lmIterate runs Levenberg-Marquardt on the TDOA system from a given
// starting (px, py). Mutates px/py in place. Returns the final
// weighted-squared residual, the iteration count, and whether the
// run produced anything usable. The damping factor lambda goes up
// when a step doesn't reduce residual (more conservative, like
// gradient descent) and down when it does (back to Newton-Gauss).
//
// The stations slice is read-only here; the encoding is the local
// type from Solve(): each entry has x, y, z (ENU meters), t (seconds
// from common epoch), w (weight = 1/sigma).
func lmIterate(stations []mlatStation, px, py *float64, pz float64) (float64, int, bool) {
	const maxIter = 100
	const convergeM = 0.01 // 1 cm
	const lambdaMin = 1e-9
	const lambdaMax = 1e9
	lambda := 1e-3

	prevResidual := math.Inf(1)
	iter := 0
	for ; iter < maxIter; iter++ {
		ref := stations[0]
		dxRef := *px - ref.x
		dyRef := *py - ref.y
		dzRef := pz - ref.z
		distRef := math.Sqrt(dxRef*dxRef + dyRef*dyRef + dzRef*dzRef)
		if distRef < 1e-3 {
			distRef = 1e-3
		}

		var jtwj [2][2]float64
		var jtwr [2]float64
		residual := 0.0
		for i := 1; i < len(stations); i++ {
			s := stations[i]
			dx := *px - s.x
			dy := *py - s.y
			dz := pz - s.z
			dist := math.Sqrt(dx*dx + dy*dy + dz*dz)
			if dist < 1e-3 {
				dist = 1e-3
			}

			currentTdoa := dist - distRef
			measuredTdoa := speedOfLight * (s.t - ref.t)
			r := measuredTdoa - currentTdoa

			w := s.w
			if ref.w < w {
				w = ref.w
			}

			jx := dx/dist - dxRef/distRef
			jy := dy/dist - dyRef/distRef

			jtwj[0][0] += w * jx * jx
			jtwj[0][1] += w * jx * jy
			jtwj[1][0] += w * jy * jx
			jtwj[1][1] += w * jy * jy
			jtwr[0] += w * jx * r
			jtwr[1] += w * jy * r
			residual += w * r * r
		}

		// Apply LM damping: add lambda*diag(J^T W J) to J^T W J.
		augA00 := jtwj[0][0] * (1 + lambda)
		augA11 := jtwj[1][1] * (1 + lambda)
		det := augA00*augA11 - jtwj[0][1]*jtwj[1][0]
		if math.Abs(det) < 1e-15 {
			// Degenerate; bump lambda and retry.
			lambda *= 10
			if lambda > lambdaMax {
				return residual, iter, residual < math.Inf(1)
			}
			continue
		}
		dPx := (augA11*jtwr[0] - jtwj[0][1]*jtwr[1]) / det
		dPy := (-jtwj[1][0]*jtwr[0] + augA00*jtwr[1]) / det

		// Trial step.
		newPx := *px + dPx
		newPy := *py + dPy

		// Score the trial: recompute residual at new point.
		trialResidual := evalResidual(stations, newPx, newPy, pz)

		if trialResidual < residual {
			// Accept step, decrease lambda (move toward Newton-Gauss).
			*px = newPx
			*py = newPy
			lambda /= 10
			if lambda < lambdaMin {
				lambda = lambdaMin
			}
			if math.Hypot(dPx, dPy) < convergeM {
				iter++
				return trialResidual, iter, true
			}
		} else {
			// Reject step, increase lambda (move toward gradient descent).
			lambda *= 10
			if lambda > lambdaMax {
				// Stuck; report whatever we have.
				return residual, iter, true
			}
		}
		prevResidual = residual
	}
	return prevResidual, iter, true
}

// evalResidual computes the weighted-squared TDOA residual at a
// candidate (px, py). Used by lmIterate to score trial steps.
func evalResidual(stations []mlatStation, px, py, pz float64) float64 {
	ref := stations[0]
	dxRef := px - ref.x
	dyRef := py - ref.y
	dzRef := pz - ref.z
	distRef := math.Sqrt(dxRef*dxRef + dyRef*dyRef + dzRef*dzRef)
	if distRef < 1e-3 {
		distRef = 1e-3
	}
	residual := 0.0
	for i := 1; i < len(stations); i++ {
		s := stations[i]
		dx := px - s.x
		dy := py - s.y
		dz := pz - s.z
		dist := math.Sqrt(dx*dx + dy*dy + dz*dz)
		if dist < 1e-3 {
			dist = 1e-3
		}
		r := speedOfLight*(s.t-ref.t) - (dist - distRef)
		w := s.w
		if ref.w < w {
			w = ref.w
		}
		residual += w * r * r
	}
	return residual
}
