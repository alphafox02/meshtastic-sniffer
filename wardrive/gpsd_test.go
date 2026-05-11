// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"testing"
	"time"
)

func TestParseGPSDEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"", "localhost", 2947},
		{"localhost", "localhost", 2947},
		{"localhost:2947", "localhost", 2947},
		{"10.0.0.5:2950", "10.0.0.5", 2950},
		{":3000", "localhost", 3000}, // colon with empty host falls back
	}
	for _, c := range cases {
		gotHost, gotPort := parseGPSDEndpoint(c.in)
		if c.wantHost == "localhost" && gotHost == "" {
			gotHost = "localhost"
		}
		if gotHost != c.wantHost || gotPort != c.wantPort {
			t.Errorf("parseGPSDEndpoint(%q) = (%q, %d); want (%q, %d)",
				c.in, gotHost, gotPort, c.wantHost, c.wantPort)
		}
	}
}

func TestParseTPV_ValidFix(t *testing.T) {
	c := &GPSDClient{}
	// Realistic gpsd TPV line.
	line := []byte(`{"class":"TPV","device":"/dev/ttyACM0","mode":3,"time":"2026-05-10T12:34:56.000Z","lat":47.6105,"lon":-122.3325,"altMSL":62.4,"speed":12.5,"track":90.0,"epx":3.1,"epy":4.2,"eph":5.0,"satellites_used":11}`)
	c.parseTPV(line)
	fix := c.Current()
	if !fix.Valid {
		t.Fatalf("expected valid fix, got invalid")
	}
	if fix.Lat != 47.6105 || fix.Lon != -122.3325 {
		t.Errorf("lat/lon = (%v,%v) want (47.6105,-122.3325)", fix.Lat, fix.Lon)
	}
	if fix.AltM != 62.4 {
		t.Errorf("alt = %v want 62.4 (altMSL preferred)", fix.AltM)
	}
	if fix.AccuracyM != 4.2 {
		t.Errorf("accuracy = %v want 4.2 (max of epx=3.1, epy=4.2)", fix.AccuracyM)
	}
	if fix.HeadingDeg != 90.0 {
		t.Errorf("heading = %v want 90", fix.HeadingDeg)
	}
	if fix.Sats != 11 {
		t.Errorf("sats = %v want 11", fix.Sats)
	}
	wantTS := time.Date(2026, 5, 10, 12, 34, 56, 0, time.UTC)
	if !fix.TS.Equal(wantTS) {
		t.Errorf("ts = %v want %v", fix.TS, wantTS)
	}
}

func TestParseTPV_FallsBackToAltWhenNoAltMSL(t *testing.T) {
	c := &GPSDClient{}
	line := []byte(`{"class":"TPV","mode":3,"lat":47.61,"lon":-122.33,"alt":55.0}`)
	c.parseTPV(line)
	if c.Current().AltM != 55.0 {
		t.Errorf("alt fallback didn't work; got %v", c.Current().AltM)
	}
}

func TestParseTPV_RejectsBadMode(t *testing.T) {
	c := &GPSDClient{}
	// mode < 2 means no 2D fix yet.
	line := []byte(`{"class":"TPV","mode":1,"lat":47.6,"lon":-122.3}`)
	c.parseTPV(line)
	if c.Current().Valid {
		t.Errorf("invalid mode shouldn't produce a valid fix")
	}
}

func TestParseTPV_IgnoresNonTPV(t *testing.T) {
	c := &GPSDClient{}
	// SKY class etc. shouldn't update the fix.
	c.parseTPV([]byte(`{"class":"SKY","satellites":[]}`))
	c.parseTPV([]byte(`{"class":"VERSION","release":"3.22"}`))
	if c.Current().Valid {
		t.Errorf("non-TPV line shouldn't produce a fix")
	}
}

func TestParseTPV_StaleFixReportedInvalid(t *testing.T) {
	c := &GPSDClient{}
	c.parseTPV([]byte(`{"class":"TPV","mode":3,"lat":47.6,"lon":-122.3}`))
	if !c.Current().Valid {
		t.Fatalf("fresh fix should be valid")
	}
	// Backdate the update by 60s; Current() should return Valid=false.
	c.mu.Lock()
	c.lastUpdate = time.Now().Add(-60 * time.Second)
	c.mu.Unlock()
	if c.Current().Valid {
		t.Errorf("60s-old fix should be reported invalid (stale)")
	}
}
