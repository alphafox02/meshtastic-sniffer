// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// meshtastic-wardrive: mobile single-node Meshtastic LoRa wardriving.
//
// Three modes:
//
//	--self-test       synthesize a deterministic drive, export to OUT_DIR
//	--capture         own a sniffer subprocess + gpsd, write to a SQLite DB
//	--export-from-db  read DB, write CSV/KML/JSON to OUT_DIR
//
// The capture mode is the live one; self-test exists for end-to-end
// review without an SDR; export-from-db re-runs the aggregator on
// stored data (so estimator-method choice is decoupled from the
// drive itself).

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	selfTest := flag.Bool("self-test", false,
		"Synthesize a deterministic 3-minute drive and export to --out-dir.")
	capture := flag.Bool("capture", false,
		"Live capture: spawn meshtastic-sniffer, subscribe to ZMQ, write to --db.")
	exportFromDB := flag.Bool("export-from-db", false,
		"Read --db and write CSV / KML / JSON to --out-dir. Re-runnable.")

	outDir := flag.String("out-dir", ".",
		"Directory for exports (created if missing).")
	dbPath := flag.String("db", "wardrive.db",
		"SQLite database file (created if missing).")
	exportSession := flag.Int64("export-session", 0,
		"Session id to export. 0 = all sessions concatenated (track polylines omitted in that mode).")

	// Capture-mode flags.
	stationID := flag.String("station-id", "",
		"Operator-supplied tag for this rig; lands in the sessions table and on every export.")
	gpsdEndpoint := flag.String("gpsd", "localhost:2947",
		"gpsd TCP endpoint (host[:port]).")
	snifferPath := flag.String("sniffer", "",
		"Path to meshtastic-sniffer binary. Empty = autodiscover. Env WARDRIVE_SNIFFER also accepted.")
	zmqEndpoint := flag.String("zmq", "tcp://127.0.0.1:7008",
		"ZMQ endpoint used by the sniffer subprocess (and the wardrive subscriber).")
	notes := flag.String("notes", "",
		"Free-text label saved on the sessions row (e.g. 'evening route 1, light traffic').")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n"+
				"  %s --self-test [--out-dir=DIR]\n"+
				"  %s --capture --db=DB [--gpsd=H:P] [--sniffer=PATH] [--station-id=ID] [sniffer flags...]\n"+
				"  %s --export-from-db --db=DB [--out-dir=DIR] [--export-session=N]\n\n"+
				"  Capture mode forwards any unknown flags to the meshtastic-sniffer subprocess.\n"+
				"  Self-test mode requires no radio, no GPS, no DB.\n"+
				"  Export-from-db mode is offline; safe to run while a capture is active.\n\n",
			os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	switch {
	case *selfTest:
		if err := runSelfTest(*outDir); err != nil {
			fmt.Fprintf(os.Stderr, "self-test: %v\n", err)
			os.Exit(1)
		}
	case *exportFromDB:
		if err := runExport(*dbPath, *outDir, *exportSession); err != nil {
			fmt.Fprintf(os.Stderr, "export: %v\n", err)
			os.Exit(1)
		}
	case *capture:
		if err := runCapture(*dbPath, *stationID, *gpsdEndpoint, *snifferPath, *zmqEndpoint, *notes, flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "capture: %v\n", err)
			os.Exit(1)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func runSelfTest(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	obs, track := SyntheticObservations()
	sess := SyntheticSession()
	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	files := []struct {
		path string
		fn   func(*os.File) error
	}{
		{outDir + "/wardrive-aggregated.csv", func(f *os.File) error { return WriteAggregatedCSV(f, sess, aggs) }},
		{outDir + "/wardrive-raw.csv", func(f *os.File) error { return WriteRawCSV(f, sess, obs) }},
		{outDir + "/wardrive.kml", func(f *os.File) error { return WriteKML(f, sess, aggs, track) }},
		{outDir + "/wardrive.json", func(f *os.File) error { return WriteJSON(f, sess, aggs, track) }},
	}
	for _, fe := range files {
		if err := writeFile(fe.path, fe.fn); err != nil {
			return err
		}
	}
	fmt.Printf("self-test wrote:\n")
	for _, fe := range files {
		fmt.Printf("  %s\n", fe.path)
	}
	fmt.Printf("\n%d observations, %d nodes, %d gps fixes\n", len(obs), len(aggs), len(track))
	for _, a := range aggs {
		fmt.Printf("  %-12s  %3d obs  best=%6.1f dBm  est=%.6f,%.6f  +/-%.0fm  (%s)\n",
			a.NodeID, a.ObsCount, a.BestRSSIdBm, a.EstLat, a.EstLon, a.EstUncertaintyM, a.EstMethod)
	}
	return nil
}

func runExport(dbPath, outDir string, sessionID int64) error {
	db, err := OpenDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	cfg := &ExportConfig{
		DB:          db,
		SessionID:   sessionID,
		OutDir:      outDir,
		WriteAggCSV: true,
		WriteRawCSV: true,
		WriteKML:    true,
		WriteJSON:   true,
	}
	return cfg.Run()
}

func runCapture(dbPath, stationID, gpsdEndpoint, snifferPath, zmqEndpoint, notes string, snifferArgs []string) error {
	// Resolve sniffer binary up-front so we fail fast rather than
	// after opening the DB.
	if snifferPath == "" {
		var err error
		snifferPath, err = FindSnifferBinary()
		if err != nil {
			return err
		}
	}

	db, err := OpenDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Stash region + preset for the session row if the sniffer args
	// carry them. Best-effort; missing values just leave the columns
	// NULL.
	region, presets := extractRegionPreset(snifferArgs)
	sessionID, _, err := db.StartSession(stationID, region, presets, "", notes)
	if err != nil {
		return err
	}
	fmt.Printf("capture: db=%s session_id=%d sniffer=%s\n", dbPath, sessionID, snifferPath)
	fmt.Printf("capture: gpsd=%s zmq=%s\n", gpsdEndpoint, zmqEndpoint)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\ncapture: signal received, shutting down...")
		cancel()
	}()

	gps := NewGPSDClient(gpsdEndpoint)
	sniff := &SnifferProc{
		BinaryPath:  snifferPath,
		Args:        snifferArgs,
		ZMQEndpoint: zmqEndpoint,
	}
	zmq := &ZMQSubscriber{Endpoint: zmqEndpoint, GPS: gps}

	cfg := &CaptureConfig{
		DB: db, SessionID: sessionID,
		Sniffer: sniff, GPS: gps, ZMQ: zmq,
	}
	return cfg.Run(ctx)
}

func extractRegionPreset(args []string) (region, presets string) {
	for _, a := range args {
		if strings.HasPrefix(a, "--region=") {
			region = strings.TrimPrefix(a, "--region=")
		}
		if strings.HasPrefix(a, "--presets=") {
			presets = strings.TrimPrefix(a, "--presets=")
		}
	}
	return
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return fn(f)
}
