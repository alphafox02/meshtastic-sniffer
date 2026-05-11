// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/export.go: read a wardrive SQLite database and write
// one or more of the supported export formats.
//
// Designed to be re-runnable: the operator can re-export at any
// time without affecting the underlying observation rows. The
// aggregator + estimator (estimate.go) run every time, so different
// estimator-method flags produce different outputs.

package main

import (
	"fmt"
	"os"
	"strconv"
)

// ExportConfig drives a single export pass.
type ExportConfig struct {
	DB        *DB
	SessionID int64  // 0 = all sessions in the DB
	OutDir    string // created if missing; output filenames are fixed

	WriteAggCSV bool
	WriteRawCSV bool
	WriteKML    bool
	WriteJSON   bool
}

// Run executes the export.
func (e *ExportConfig) Run() error {
	if err := os.MkdirAll(e.OutDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", e.OutDir, err)
	}
	obs, err := e.DB.LoadObservations(e.SessionID)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}
	if len(obs) == 0 {
		return fmt.Errorf("no observations to export (session_id=%d)", e.SessionID)
	}

	sess, track, err := e.loadSessionContext(obs)
	if err != nil {
		return err
	}

	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	if e.WriteAggCSV {
		path := e.OutDir + "/wardrive-aggregated.csv"
		if err := writeFile(path, func(f *os.File) error {
			return WriteAggregatedCSV(f, sess, aggs)
		}); err != nil {
			return err
		}
		fmt.Printf("export: wrote %s (%d nodes)\n", path, len(aggs))
	}
	if e.WriteRawCSV {
		path := e.OutDir + "/wardrive-raw.csv"
		if err := writeFile(path, func(f *os.File) error {
			return WriteRawCSV(f, sess, obs)
		}); err != nil {
			return err
		}
		fmt.Printf("export: wrote %s (%d observations)\n", path, len(obs))
	}
	if e.WriteKML {
		path := e.OutDir + "/wardrive.kml"
		if err := writeFile(path, func(f *os.File) error {
			return WriteKML(f, sess, aggs, track)
		}); err != nil {
			return err
		}
		fmt.Printf("export: wrote %s\n", path)
	}
	if e.WriteJSON {
		path := e.OutDir + "/wardrive.json"
		if err := writeFile(path, func(f *os.File) error {
			return WriteJSON(f, sess, aggs, track)
		}); err != nil {
			return err
		}
		fmt.Printf("export: wrote %s\n", path)
	}
	return nil
}

// loadSessionContext reads either a single session (when SessionID > 0)
// or fabricates a "multi" Session that spans every observation in the
// DB. Tracks are loaded from the named session or empty for multi-mode.
func (e *ExportConfig) loadSessionContext(obs []Observation) (Session, []TrackPoint, error) {
	if e.SessionID > 0 {
		sess, err := e.DB.LoadSession(e.SessionID)
		if err != nil {
			return Session{}, nil, fmt.Errorf("load session %d: %w", e.SessionID, err)
		}
		sess.SessionID = strconv.FormatInt(e.SessionID, 10)
		sess.AppRelease = AppName + "-" + AppVersion
		track, err := e.DB.LoadTracks(e.SessionID)
		if err != nil {
			return Session{}, nil, fmt.Errorf("load tracks %d: %w", e.SessionID, err)
		}
		return sess, track, nil
	}
	// All sessions: synthesize a multi-session header from
	// observation time bounds. Track polylines are omitted -- they
	// would smear together across sessions; a per-session export is
	// the right move when track polylines are wanted.
	start, end := SessionWindow(obs)
	return Session{
		SessionID:  "all",
		StartTS:    start,
		EndTS:      end,
		AppRelease: AppName + "-" + AppVersion,
	}, nil, nil
}
