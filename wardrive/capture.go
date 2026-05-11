// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/capture.go: orchestrate the live capture path.
//
// Three goroutines tied together by `ctx`:
//
//	gpsd subscriber  -- maintains the current operator GPS fix
//	zmq subscriber   -- consumes sniffer events, tags with GPS,
//	                    emits Observations
//	track writer     -- on a fixed cadence, snapshots the GPS fix
//	                    and writes it to the tracks table
//
// The main loop drains the observations channel into the database
// and prints a one-line status every 5 seconds. The sniffer
// subprocess runs in a fourth goroutine; when it exits, capture
// shuts down.

package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// CaptureConfig bundles the wiring inputs. All fields are required
// except StartTrackCadence which defaults to 1s.
type CaptureConfig struct {
	DB           *DB
	SessionID    int64
	Sniffer      *SnifferProc
	GPS          *GPSDClient
	ZMQ          *ZMQSubscriber
	TrackCadence time.Duration // 0 = default 1s
}

// Run blocks until ctx is cancelled or the sniffer subprocess
// exits. Stamps EndSession on the database row before returning.
func (cfg *CaptureConfig) Run(ctx context.Context) error {
	if cfg.TrackCadence == 0 {
		cfg.TrackCadence = 1 * time.Second
	}

	// Counters for the status line.
	var nObs uint64
	var nTracks uint64

	// gpsd in its own goroutine.
	gpsCtx, cancelGPS := context.WithCancel(ctx)
	defer cancelGPS()
	go cfg.GPS.Run(gpsCtx)

	// Sniffer subprocess in its own goroutine. When it exits we
	// signal the parent ctx so the capture loop unwinds.
	captureCtx, cancelCapture := context.WithCancel(ctx)
	defer cancelCapture()
	snifferDone := make(chan error, 1)
	go func() {
		err := cfg.Sniffer.Start(captureCtx)
		snifferDone <- err
		cancelCapture()
	}()

	// ZMQ subscriber emits Observations onto obs.
	obs := make(chan *Observation, 256)
	go cfg.ZMQ.Run(captureCtx, obs)

	// Track writer ticks on cadence and snapshots the GPS fix.
	trackTicker := time.NewTicker(cfg.TrackCadence)
	defer trackTicker.Stop()

	// Status printer every 5s.
	statusTicker := time.NewTicker(5 * time.Second)
	defer statusTicker.Stop()

	log.Printf("capture: session_id=%d started", cfg.SessionID)
	startTS := time.Now()

	for {
		select {
		case <-captureCtx.Done():
			err := <-snifferDone
			_ = cfg.DB.EndSession(cfg.SessionID)
			log.Printf("capture: session %d ended after %s (%d obs, %d tracks)",
				cfg.SessionID, time.Since(startTS).Round(time.Second),
				atomic.LoadUint64(&nObs), atomic.LoadUint64(&nTracks))
			return err
		case o, ok := <-obs:
			if !ok {
				obs = nil // channel closed; treat as a sniffer-end signal
				cancelCapture()
				continue
			}
			if err := cfg.DB.InsertObservation(cfg.SessionID, o); err != nil {
				log.Printf("capture: insert obs: %v", err)
				continue
			}
			atomic.AddUint64(&nObs, 1)
		case <-trackTicker.C:
			fix := cfg.GPS.Current()
			if !fix.Valid {
				continue
			}
			tp := &TrackPoint{
				TS: fix.TS, Lat: fix.Lat, Lon: fix.Lon, AltM: fix.AltM,
				SpeedMps: fix.SpeedMps, HeadingDeg: fix.HeadingDeg,
				HDOP: fix.HDOP, Sats: fix.Sats,
			}
			if err := cfg.DB.InsertTrack(cfg.SessionID, tp); err != nil {
				log.Printf("capture: insert track: %v", err)
				continue
			}
			atomic.AddUint64(&nTracks, 1)
		case <-statusTicker.C:
			fix := cfg.GPS.Current()
			gpsLabel := "no-fix"
			if fix.Valid {
				gpsLabel = "fix"
			}
			log.Printf("capture: %d obs, %d tracks, gps=%s",
				atomic.LoadUint64(&nObs), atomic.LoadUint64(&nTracks), gpsLabel)
		}
	}
}
