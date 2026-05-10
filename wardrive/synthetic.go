// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/synthetic.go: deterministic fixture data for --self-test
// and for the format-emitter tests.
//
// Three nodes with deliberately different shapes so a reviewer (or a
// WiGLE engineer reading the sample export) sees the spectrum of
// what we'd ship in real captures:
//
//   alpha   -- decrypted, NodeInfo seen, no self-report -> centroid
//   bravo   -- encrypted (channel unknown), centroid only
//   charlie -- decrypted + self-reported POSITION -> uses self-report
//
// Operator drives a small box loop sampled at 0.5 Hz for ~3 minutes,
// hearing each node from a few different bearings.

package main

import (
	"math"
	"time"
)

// FixtureCenter is roughly the corner of 4th & Pike in downtown
// Seattle. Picked because Google Earth has good imagery there for
// reviewing the KML output by eye.
var fixtureCenter = struct{ Lat, Lon float64 }{
	Lat: 47.6097,
	Lon: -122.3331,
}

// SyntheticObservations returns a deterministic slice of Observations
// representing a 3-minute drive around the fixture center with three
// Meshtastic nodes audible at varying RSSI.
func SyntheticObservations() ([]Observation, []TrackPoint) {
	t0 := time.Date(2026, 5, 10, 18, 0, 0, 0, time.UTC)

	// Node positions (truth). Estimator should land near these.
	nodes := []struct {
		ID, LongName, ShortName, ChannelName, Preset string
		ChannelHash                                  uint8
		BWHz                                         uint32
		FreqHz                                       uint64
		Role                                         uint32
		HWModel                                      uint32
		Lat, Lon                                     float64
		TxPdBm                                       float64
		HasSelfReport                                bool
	}{
		{
			ID: "!433c0b98", LongName: "Alpha Router", ShortName: "ALPH",
			ChannelName: "LongFast", Preset: "LongFast", ChannelHash: 0x7e,
			BWHz: 250000, FreqHz: 906875000, Role: 2, HWModel: 32,
			Lat:  fixtureCenter.Lat + 0.0008,
			Lon:  fixtureCenter.Lon + 0.0006,
			TxPdBm: 22, HasSelfReport: false,
		},
		{
			ID: "!8a17d402", // encrypted-only
			ChannelHash: 0xab,
			BWHz: 250000, FreqHz: 907125000, // some other slot
			Lat:  fixtureCenter.Lat - 0.0009,
			Lon:  fixtureCenter.Lon + 0.0011,
			TxPdBm: 17, HasSelfReport: false,
			Preset: "LongFast",
		},
		{
			ID: "!471c1b98", LongName: "Charlie Tracker", ShortName: "CHRL",
			ChannelName: "MyHomeChannel", Preset: "MediumFast", ChannelHash: 0x42,
			BWHz: 250000, FreqHz: 906625000, Role: 4, HWModel: 41,
			Lat:  fixtureCenter.Lat + 0.0002,
			Lon:  fixtureCenter.Lon - 0.0014,
			TxPdBm: 14, HasSelfReport: true,
		},
	}

	// Operator track: small rectangular loop at ~30 mph (~13 m/s),
	// sampled at 0.5 Hz. ~3 minutes total.
	const dt = 2 * time.Second
	const numFixes = 90
	track := make([]TrackPoint, 0, numFixes)
	obs := make([]Observation, 0, numFixes*len(nodes))

	for i := 0; i < numFixes; i++ {
		ts := t0.Add(time.Duration(i) * dt)
		// Parametric box loop centered on the fixture.
		theta := 2 * math.Pi * float64(i) / float64(numFixes)
		latOff := 0.0010 * math.Sin(theta)
		lonOff := 0.0014 * math.Cos(theta)
		rxLat := fixtureCenter.Lat + latOff
		rxLon := fixtureCenter.Lon + lonOff
		track = append(track, TrackPoint{
			TS: ts, Lat: rxLat, Lon: rxLon, AltM: 65, SpeedMps: 13,
			HeadingDeg: math.Mod(180.0/math.Pi*theta, 360),
			HDOP: 1.4, Sats: 11,
		})

		// One observation per node per fix, RSSI from a free-space
		// path-loss-ish model so the centroid biases toward each
		// node's true location.
		for _, n := range nodes {
			d := haversineMeters(rxLat, rxLon, n.Lat, n.Lon)
			if d < 5 {
				d = 5
			}
			// Simple log-distance: RSSI = TxP - 10*n*log10(d/d0) - PL(d0)
			// Constants chosen so values land in the plausible -60 to -110 dBm
			// range across the loop.
			plD0 := 40.0  // dB at 1 m reference
			pleN := 2.5   // path-loss exponent
			rssi := n.TxPdBm - plD0 - 10*pleN*math.Log10(d/1.0)
			snr := rssi - (-115) // approximate SNR vs noise floor
			if snr < -10 {
				snr = -10
			}
			crcOK := true
			o := Observation{
				TS:           ts,
				NodeID:       n.ID,
				PacketID:     uint32(1000 + i),
				RxLat:        rxLat,
				RxLon:        rxLon,
				RxAltM:       65,
				RxSpeedMps:   13,
				RxHeadingDeg: math.Mod(180.0/math.Pi*theta, 360),
				HDOP:         1.4,
				Sats:         11,
				RSSIdBm:      rssi,
				SNRdB:        snr,
				FreqHz:       n.FreqHz,
				BWHz:         n.BWHz,
				Preset:       n.Preset,
				ChannelHash:  n.ChannelHash,
				ChannelName:  n.ChannelName,
				Decrypted:    n.ChannelName != "",
				PortName:     "TEXT_MESSAGE_APP",
				PayloadCRCOk: &crcOK,
				HopLimit:     3,
				HopStart:     3,
			}
			// First observation latches NodeInfo (when decrypted) so
			// the aggregate has names + role + hw model.
			if i == 0 && n.LongName != "" {
				o.LongName = n.LongName
				o.ShortName = n.ShortName
				o.Role = n.Role
				o.HWModel = n.HWModel
			}
			// Charlie broadcasts position halfway through the run.
			if n.HasSelfReport && i == numFixes/2 {
				o.SelfReportedLat = n.Lat
				o.SelfReportedLon = n.Lon
				o.SelfReportedAltM = 60
			}
			obs = append(obs, o)
		}
	}
	return obs, track
}

// SyntheticSession is the canonical Session metadata that pairs with
// SyntheticObservations(); used by --self-test and the export tests
// so output is deterministic and diff-stable.
func SyntheticSession() Session {
	t0 := time.Date(2026, 5, 10, 18, 0, 0, 0, time.UTC)
	return Session{
		SessionID:  "selftest-1",
		StationID:  "fixture-rx",
		SDR:        "synthetic",
		Region:     "US",
		Presets:    "LongFast,MediumFast",
		StartTS:    t0,
		EndTS:      t0.Add(3 * time.Minute),
		AppRelease: AppName + "-" + AppVersion,
	}
}
