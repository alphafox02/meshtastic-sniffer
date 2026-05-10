// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// meshtastic-wardrive: mobile single-node Meshtastic LoRa wardriving.
//
// Phase 1 of the build: format-emitter scaffolding + a --self-test
// mode that synthesizes a deterministic 3-minute drive and writes
// CSV + KML + sidecar JSON. Lets us mail sample exports to WiGLE
// (and review in Google Earth) before the radio/GPS capture path
// is wired up.
//
// Capture mode (sniffer subprocess + gpsd + SQLite) lands in a
// follow-on commit.

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	selfTest := flag.Bool("self-test", false,
		"Synthesize a deterministic 3-minute drive and write CSV/KML/JSON to --out-dir.")
	outDir := flag.String("out-dir", ".",
		"Directory for --self-test outputs (default current directory).")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s --self-test [--out-dir=DIR]\n\n"+
				"Phase-1 scaffold: emits sample CSV / KML / JSON from a deterministic\n"+
				"synthetic drive so the format can be reviewed before radio capture\n"+
				"is wired up. Live capture mode lands in a follow-on commit.\n\nFlags:\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if !*selfTest {
		flag.Usage()
		os.Exit(2)
	}

	if err := runSelfTest(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "self-test: %v\n", err)
		os.Exit(1)
	}
}

func runSelfTest(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	obs, track := SyntheticObservations()
	sess := SyntheticSession()
	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	csvPath := outDir + "/wardrive-aggregated.csv"
	rawPath := outDir + "/wardrive-raw.csv"
	kmlPath := outDir + "/wardrive.kml"
	jsonPath := outDir + "/wardrive.json"

	if err := writeFile(csvPath, func(f *os.File) error {
		return WriteAggregatedCSV(f, sess, aggs)
	}); err != nil {
		return err
	}
	if err := writeFile(rawPath, func(f *os.File) error {
		return WriteRawCSV(f, sess, obs)
	}); err != nil {
		return err
	}
	if err := writeFile(kmlPath, func(f *os.File) error {
		return WriteKML(f, sess, aggs, track)
	}); err != nil {
		return err
	}
	if err := writeFile(jsonPath, func(f *os.File) error {
		return WriteJSON(f, sess, aggs, track)
	}); err != nil {
		return err
	}

	fmt.Printf("self-test wrote:\n  %s\n  %s\n  %s\n  %s\n",
		csvPath, rawPath, kmlPath, jsonPath)
	fmt.Printf("\n%d observations, %d nodes, %d gps fixes\n", len(obs), len(aggs), len(track))
	for _, a := range aggs {
		fmt.Printf("  %-12s  %3d obs  best=%6.1f dBm  est=%.6f,%.6f  +/-%.0fm  (%s)\n",
			a.NodeID, a.ObsCount, a.BestRSSIdBm, a.EstLat, a.EstLon, a.EstUncertaintyM, a.EstMethod)
	}
	return nil
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := fn(f); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
