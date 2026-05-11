// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func openTempDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardrive.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDB_StartAndEndSession(t *testing.T) {
	db := openTempDB(t)
	id, start, err := db.StartSession("rooftop", "US", "LongFast", "1.0", "note")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if id <= 0 {
		t.Errorf("session id = %d; want > 0", id)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("session start time skewed: %v", start)
	}
	if err := db.EndSession(id); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	sess, err := db.LoadSession(id)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if sess.StationID != "rooftop" || sess.Region != "US" || sess.Presets != "LongFast" {
		t.Errorf("session round-trip wrong: %+v", sess)
	}
	if sess.EndTS.IsZero() {
		t.Error("EndTS not set")
	}
}

func TestDB_InsertAndLoadObservation(t *testing.T) {
	db := openTempDB(t)
	sid, _, _ := db.StartSession("rx", "", "", "", "")
	crcOK := true
	obs := Observation{
		TS:           time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		NodeID:       "!433c0b98",
		PacketID:     1234,
		RxLat:        47.61, RxLon: -122.33, RxAltM: 60,
		RxSpeedMps: 12.5, RxHeadingDeg: 90, HDOP: 1.2, Sats: 11,
		RSSIdBm:     -65.5,
		SNRdB:       12.3,
		FreqHz:      906875000,
		BWHz:        250000,
		Preset:      "LongFast",
		ChannelHash: 0x7e,
		ChannelName: "LongFast",
		Decrypted:   true,
		PortName:    "TEXT_MESSAGE_APP",
		PayloadCRCOk: &crcOK,
		HopLimit:    3,
		HopStart:    3,
		LongName:    "Alpha",
		ShortName:   "AL",
		HWModel:     32,
		Role:        2,
	}
	if err := db.InsertObservation(sid, &obs); err != nil {
		t.Fatalf("InsertObservation: %v", err)
	}
	loaded, err := db.LoadObservations(sid)
	if err != nil {
		t.Fatalf("LoadObservations: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("got %d obs want 1", len(loaded))
	}
	got := loaded[0]
	// Spot-check the round-trip on a representative subset of fields.
	if got.NodeID != "!433c0b98" {
		t.Errorf("NodeID=%q want !433c0b98", got.NodeID)
	}
	if got.RxLat != 47.61 || got.RxLon != -122.33 {
		t.Errorf("Rx=(%v,%v) want (47.61,-122.33)", got.RxLat, got.RxLon)
	}
	if got.RSSIdBm != -65.5 {
		t.Errorf("RSSI=%v want -65.5", got.RSSIdBm)
	}
	if got.ChannelHash != 0x7e {
		t.Errorf("ChannelHash=%v want 0x7e", got.ChannelHash)
	}
	if got.LongName != "Alpha" {
		t.Errorf("LongName=%q want Alpha", got.LongName)
	}
	if got.PayloadCRCOk == nil || !*got.PayloadCRCOk {
		t.Errorf("PayloadCRCOk round-trip lost: %v", got.PayloadCRCOk)
	}
	if got.HWModel != 32 || got.Role != 2 {
		t.Errorf("HWModel=%v Role=%v want 32, 2", got.HWModel, got.Role)
	}
}

func TestDB_InsertTrackAndLoad(t *testing.T) {
	db := openTempDB(t)
	sid, _, _ := db.StartSession("rx", "", "", "", "")
	for i := 0; i < 5; i++ {
		tp := &TrackPoint{
			TS:  time.Date(2026, 5, 10, 12, 0, i, 0, time.UTC),
			Lat: 47.61, Lon: -122.33, AltM: 60, SpeedMps: 12,
			HeadingDeg: 90, HDOP: 1.1, Sats: 10,
		}
		if err := db.InsertTrack(sid, tp); err != nil {
			t.Fatalf("InsertTrack %d: %v", i, err)
		}
	}
	track, err := db.LoadTracks(sid)
	if err != nil {
		t.Fatalf("LoadTracks: %v", err)
	}
	if len(track) != 5 {
		t.Errorf("got %d tracks want 5", len(track))
	}
	if track[0].Lat != 47.61 || track[0].Lon != -122.33 {
		t.Errorf("first track wrong: %+v", track[0])
	}
}

func TestDB_CountObservations(t *testing.T) {
	db := openTempDB(t)
	sid, _, _ := db.StartSession("rx", "", "", "", "")
	for i := 0; i < 7; i++ {
		_ = db.InsertObservation(sid, &Observation{
			TS: time.Now().UTC(), NodeID: "!xxxxxxxx", RSSIdBm: -70,
		})
	}
	got, err := db.CountObservations(sid)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if got != 7 {
		t.Errorf("CountObservations(%d)=%d want 7", sid, got)
	}
	all, _ := db.CountObservations(0)
	if all != 7 {
		t.Errorf("CountObservations(all)=%d want 7", all)
	}
}

func TestDB_PersistsAcrossClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.db")
	db1, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB 1: %v", err)
	}
	sid, _, _ := db1.StartSession("rx", "", "", "", "")
	_ = db1.InsertObservation(sid, &Observation{
		TS: time.Now().UTC(), NodeID: "!aaaaaaaa", RSSIdBm: -55,
	})
	if err := db1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	db2, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB 2: %v", err)
	}
	defer db2.Close()
	n, _ := db2.CountObservations(0)
	if n != 1 {
		t.Errorf("post-reopen count=%d want 1", n)
	}
	sessions, _ := db2.ListSessions()
	if len(sessions) != 1 {
		t.Errorf("post-reopen sessions=%d want 1", len(sessions))
	}
}
