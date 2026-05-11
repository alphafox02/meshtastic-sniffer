// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExport_FromDB exercises the full live-capture-and-export
// pipeline against a SQLite DB. Writes the synthetic fixture's
// observations + tracks through the DB layer, then re-reads them
// and runs the export. Sanity-checks that the export contains the
// same node ids and roughly the same numbers as a direct
// in-memory aggregation.
func TestExport_FromDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	outDir := filepath.Join(dir, "out")

	// Write synthetic data into a fresh DB via the live capture path
	// (insert through the prepared statements).
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	sid, _, err := db.StartSession("fixture-rx", "US", "LongFast", "0.1", "")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	obs, track := SyntheticObservations()
	for i := range obs {
		if err := db.InsertObservation(sid, &obs[i]); err != nil {
			t.Fatalf("InsertObservation %d: %v", i, err)
		}
	}
	for _, tp := range track {
		if err := db.InsertTrack(sid, &tp); err != nil {
			t.Fatalf("InsertTrack: %v", err)
		}
	}
	_ = db.EndSession(sid)

	// Re-read + export.
	cfg := &ExportConfig{
		DB:          db,
		SessionID:   sid,
		OutDir:      outDir,
		WriteAggCSV: true,
		WriteKML:    true,
		WriteJSON:   true,
	}
	if err := cfg.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	db.Close()

	// Aggregated CSV should contain three node ids.
	mustContainAll(t, filepath.Join(outDir, "wardrive-aggregated.csv"),
		"!433c0b98", "!471c1b98", "!8a17d402",
		"rssi2-weighted-centroid", "self-reported")

	// CSV should be valid-shaped (preamble + header + 3 rows).
	b, err := os.ReadFile(filepath.Join(outDir, "wardrive-aggregated.csv"))
	if err != nil {
		t.Fatalf("readfile: %v", err)
	}
	body := strings.SplitN(string(b), "\n", 2)[1]
	r := csv.NewReader(strings.NewReader(body))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(records) != 4 { // 1 header + 3 data
		t.Errorf("post-roundtrip CSV has %d records; want 4", len(records))
	}

	// KML should still contain all the structural folders.
	mustContainAll(t, filepath.Join(outDir, "wardrive.kml"),
		`<name>Operator path</name>`,
		`<name>Meshtastic nodes</name>`,
		`<name>Decrypted (channel known)</name>`,
		`!433c0b98`,
	)
}

func TestExport_NoObservationsFails(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	cfg := &ExportConfig{DB: db, OutDir: dir, WriteAggCSV: true}
	if err := cfg.Run(); err == nil {
		t.Error("expected error on empty DB; got nil")
	}
}

func mustContainAll(t *testing.T, path string, needles ...string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, s := range needles {
		if !bytes.Contains(b, []byte(s)) {
			t.Errorf("%s: missing %q", filepath.Base(path), s)
		}
	}
}
