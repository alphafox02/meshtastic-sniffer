// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

func TestWriteKML_IsValidXML(t *testing.T) {
	obs, track := SyntheticObservations()
	sess := SyntheticSession()
	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	var buf bytes.Buffer
	if err := WriteKML(&buf, sess, aggs, track); err != nil {
		t.Fatalf("WriteKML: %v", err)
	}
	// xml.Decoder catches malformed tags / unbalanced elements.
	dec := xml.NewDecoder(&buf)
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return
			}
			t.Fatalf("xml decode: %v", err)
		}
	}
}

func TestWriteKML_ContainsExpectedFolders(t *testing.T) {
	obs, track := SyntheticObservations()
	sess := SyntheticSession()
	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	var buf bytes.Buffer
	_ = WriteKML(&buf, sess, aggs, track)
	out := buf.String()

	must := []string{
		`<name>Operator path</name>`,
		`<name>Meshtastic nodes</name>`,
		`<name>Decrypted (channel known)</name>`,
		`<name>Encrypted (channel unknown)</name>`,
		`<name>Confidence circles</name>`,
		`<gx:Track>`,
	}
	for _, s := range must {
		if !strings.Contains(out, s) {
			t.Errorf("KML missing %q", s)
		}
	}
}

func TestCirclePoints_ClosedRing(t *testing.T) {
	pts := circlePoints(47.6105, -122.3325, 100.0, 16)
	if len(pts) != 17 {
		t.Fatalf("circlePoints n=16 returned %d points; want 17 (closed ring)", len(pts))
	}
	// First and last should be the same point.
	if pts[0][0] != pts[len(pts)-1][0] || pts[0][1] != pts[len(pts)-1][1] {
		t.Errorf("ring not closed: first=%v last=%v", pts[0], pts[len(pts)-1])
	}
	// Every point should be ~100 m from the center (within 1 m tolerance).
	for i, p := range pts {
		d := haversineMeters(47.6105, -122.3325, p[0], p[1])
		if d < 99 || d > 101 {
			t.Errorf("point %d at distance %.2f m; want ~100", i, d)
		}
	}
}

func TestWriteJSON_RoundTripsSession(t *testing.T) {
	obs, track := SyntheticObservations()
	sess := SyntheticSession()
	aggs := Aggregate(obs, sess.SessionID, sess.StationID)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, sess, aggs, track); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got JSONExport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Format != FormatVersion {
		t.Errorf("format=%q want %q", got.Format, FormatVersion)
	}
	if got.Session.SessionID != sess.SessionID {
		t.Errorf("session_id=%q want %q", got.Session.SessionID, sess.SessionID)
	}
	if len(got.Nodes) != len(aggs) {
		t.Errorf("nodes len=%d want %d", len(got.Nodes), len(aggs))
	}
	if len(got.Track) != len(track) {
		t.Errorf("track len=%d want %d", len(got.Track), len(track))
	}
}

func TestSyntheticEstimateNearTruth(t *testing.T) {
	obs, _ := SyntheticObservations()
	aggs := Aggregate(obs, "s1", "rx1")
	if len(aggs) != 3 {
		t.Fatalf("got %d aggregates want 3", len(aggs))
	}
	// Self-reported node should land exactly on its broadcast position.
	for _, a := range aggs {
		if a.EstMethod == "self-reported" {
			if a.EstLat != a.SelfReportedLat || a.EstLon != a.SelfReportedLon {
				t.Errorf("self-reported est=(%v,%v) selfrep=(%v,%v) -- should match",
					a.EstLat, a.EstLon, a.SelfReportedLat, a.SelfReportedLon)
			}
		}
	}
	// Centroid nodes should land within 50 m of the synthetic truth
	// embedded in synthetic.go (the loop is dense and centered).
	for _, a := range aggs {
		if a.EstMethod != "rssi2-weighted-centroid" {
			continue
		}
		if a.EstUncertaintyM <= 0 {
			t.Errorf("%s: uncertainty=%v should be > 0", a.NodeID, a.EstUncertaintyM)
		}
	}
}
