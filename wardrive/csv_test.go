// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func TestPreamble_StableShape(t *testing.T) {
	sess := Session{
		SessionID:  "s1",
		StationID:  "rooftop",
		SDR:        "hackrf",
		Region:     "US",
		Presets:    "LongFast,MediumFast",
		AppRelease: "meshtastic-wardrive-1.0.0",
	}
	got := PreambleLine(sess)
	want := "MeshtasticWardrive-1.0,appRelease=meshtastic-wardrive-1.0.0,sdr=hackrf,region=US,presets=LongFast;MediumFast,station=rooftop,session_id=s1"
	if got != want {
		t.Errorf("PreambleLine() = %q\nwant                %q", got, want)
	}
	// Must split into exactly 7 comma-separated parts even though
	// presets contains a literal comma in input.
	parts := strings.Split(got, ",")
	if len(parts) != 7 {
		t.Errorf("naive split got %d parts; want 7 (preamble must be safe to split-on-comma)", len(parts))
	}
}

func TestPreamble_OmitsEmptyFields(t *testing.T) {
	got := PreambleLine(Session{AppRelease: "x-1"})
	want := "MeshtasticWardrive-1.0,appRelease=x-1"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestSanitizePreambleValue(t *testing.T) {
	cases := map[string]string{
		"plain":     "plain",
		"a,b":       "a;b",
		"a=b":       "a_b",
		"a\nb":      "a b",
		"a,b=c\nd":  "a;b_c d",
	}
	for in, want := range cases {
		got := sanitizePreambleValue(in)
		if got != want {
			t.Errorf("sanitize(%q) = %q want %q", in, got, want)
		}
	}
}

func TestWriteAggregatedCSV_HeaderAndRows(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	aggs := []*NodeAggregate{{
		NodeID:          "!aaaaaaaa",
		LongName:        "Alpha",
		ShortName:       "AL",
		HWModel:         32,
		Role:            2,
		ChannelName:     "LongFast",
		ChannelHash:     0x7e,
		Preset:          "LongFast",
		BWHz:            250000,
		FreqHz:          906875000,
		FirstSeen:       t0,
		LastSeen:        t0.Add(time.Minute),
		ObsCount:        12,
		BestRSSIdBm:     -55.5,
		BestRSSITS:      t0.Add(30 * time.Second),
		BestSNRdB:       8.2,
		EstLat:          47.6105,
		EstLon:          -122.3325,
		EstUncertaintyM: 78.4,
		EstMethod:       "rssi2-weighted-centroid",
		SessionID:       "sess1",
		StationID:       "rx1",
	}}
	var buf bytes.Buffer
	if err := WriteAggregatedCSV(&buf, Session{AppRelease: "x"}, aggs); err != nil {
		t.Fatalf("WriteAggregatedCSV: %v", err)
	}
	out := buf.String()

	// Preamble first
	if !strings.HasPrefix(out, "MeshtasticWardrive-1.0,") {
		t.Errorf("output does not start with format tag: %s", out[:64])
	}

	// Re-parse the body (skip preamble) to confirm it's valid CSV
	// with the expected number of columns.
	body := strings.SplitN(out, "\n", 2)[1]
	r := csv.NewReader(strings.NewReader(body))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 data row; got %d records", len(records))
	}
	if len(records[0]) != len(AggregatedCSVHeader) {
		t.Fatalf("header has %d cols want %d", len(records[0]), len(AggregatedCSVHeader))
	}
	if len(records[1]) != len(AggregatedCSVHeader) {
		t.Fatalf("data row has %d cols want %d", len(records[1]), len(AggregatedCSVHeader))
	}
	// Spot-check a couple of fields by index.
	if records[1][0] != "!aaaaaaaa" {
		t.Errorf("col0 (node_id) = %q want %q", records[1][0], "!aaaaaaaa")
	}
	if records[1][6] != "0x7e" {
		t.Errorf("col6 (channel_hash) = %q want 0x7e", records[1][6])
	}
}

func TestWriteRawCSV_HeaderAndRowCount(t *testing.T) {
	obs, _ := SyntheticObservations()
	var buf bytes.Buffer
	if err := WriteRawCSV(&buf, SyntheticSession(), obs); err != nil {
		t.Fatalf("WriteRawCSV: %v", err)
	}
	body := strings.SplitN(buf.String(), "\n", 2)[1]
	r := csv.NewReader(strings.NewReader(body))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse: %v", err)
	}
	// 1 header + N observations
	if len(records) != 1+len(obs) {
		t.Fatalf("got %d records, want 1 + %d observations", len(records), len(obs))
	}
}
