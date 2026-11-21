// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func kmlWellFormed(t *testing.T, doc string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(doc))
	for {
		if _, err := d.Token(); err == io.EOF {
			return
		} else if err != nil {
			t.Fatalf("KML not well-formed: %v\n%s", err, doc)
		}
	}
}

func feedString(k *KMLLive, sensors []Sensor, now time.Time) string {
	var b bytes.Buffer
	k.WriteFeed(&b, sensors, now)
	return b.String()
}

func TestKML_TrustAndRejects(t *testing.T) {
	k := NewKMLLive()
	now := time.Unix(1_800_000_000, 0)
	// Untrusted position: ignored.
	k.NoteFrame([]byte(`{"from":"!00000001","station":"a","lat":45.1,"lon":9.1,"fields_trusted":false}`), now)
	// (0,0) no-fix sentinel and out-of-range: ignored.
	k.NoteFrame([]byte(`{"from":"!00000002","station":"a","lat":0,"lon":0,"fields_trusted":true}`), now)
	k.NoteFrame([]byte(`{"from":"!00000003","station":"a","lat":91,"lon":9,"fields_trusted":true}`), now)
	// Non-frame events: ignored.
	k.NoteFrame([]byte(`{"event":"STATS","from":"!00000004","lat":45,"lon":9,"fields_trusted":true}`), now)
	// Older sniffer without fields_trusted: decrypted=true counts.
	k.NoteFrame([]byte(`{"from":"!00000005","station":"a","lat":45.5,"lon":9.5,"decrypted":true}`), now)
	doc := feedString(k, nil, now)
	kmlWellFormed(t, doc)
	if !strings.Contains(doc, "0 sensor(s), 1 node(s), 0 multilateration fix(es)") {
		t.Fatalf("want exactly one node:\n%s", doc)
	}
	if !strings.Contains(doc, "<name>!00000005</name>") {
		t.Fatalf("decrypted legacy frame not plotted")
	}
}

func TestKML_TrackNamesHeardBy(t *testing.T) {
	k := NewKMLLive()
	t0 := time.Unix(1_800_000_000, 0)
	k.NoteFrame([]byte(`{"from":"!a1b2c3d4","long_name":"Base <Camp> & Co","short_name":"BC","fields_trusted":true}`), t0)
	// Same packet heard by two stations: one track point, two heard-by.
	k.NoteFrame([]byte(`{"from":"!a1b2c3d4","station":"north","station_lat":45.0,"station_lon":9.0,"lat":45.1,"lon":9.1,"alt_m":120,"snr_db":5.5,"channel_name":"Long<Fast>","fields_trusted":true}`), t0)
	k.NoteFrame([]byte(`{"from":"!a1b2c3d4","station":"south","lat":45.1,"lon":9.1,"alt_m":120,"snr_db":-3,"fields_trusted":true}`), t0)
	k.NoteFrame([]byte(`{"from":"!a1b2c3d4","station":"north","station_lat":45.0,"station_lon":9.0,"lat":45.2,"lon":9.2,"alt_m":130,"fields_trusted":true}`), t0.Add(time.Minute))
	sensors := []Sensor{{Name: "south", Lat: 44.9, Lon: 9.3}, {Name: "north", Lat: 1, Lon: 1}}
	doc := feedString(k, sensors, t0.Add(2*time.Minute))
	kmlWellFormed(t, doc)

	for _, want := range []string{
		"2 sensor(s), 1 node(s)",
		"<name>Base &lt;Camp&gt; &amp; Co [BC]</name>",
		// HTML description: channel double-escaped, lines joined by <br>.
		"Channel: Long&amp;lt;Fast&amp;gt;&lt;br&gt;",
		"Position reports: 3, track points: 2",
		"9.100000,45.100000,120.0",
		"9.200000,45.200000,130.0",
		"<name>Heard by north</name>",
		"<name>Heard by south</name>",
		// Live gpsd position (45.0, 9.0) overrides the registry's (1, 1).
		"9.000000,45.000000,0.0",
		"gpsd position, last reported",
		"configured position (sensor registry)",
		"<altitudeMode>absolute</altitudeMode>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(doc, "<Camp>") || strings.Contains(doc, "<TimeStamp>") {
		t.Errorf("raw markup or TimeStamp leaked:\n%s", doc)
	}
	// Heard-by lines older than kmlHeardByFresh are dropped; stale style after an hour.
	doc = feedString(k, sensors, t0.Add(2*time.Hour))
	if strings.Contains(doc, "<name>Heard by") {
		t.Errorf("stale heard-by line drawn")
	}
	if !strings.Contains(doc, "#node-stale") {
		t.Errorf("node not marked stale after an hour")
	}
}

func TestKML_Fixes(t *testing.T) {
	k := NewKMLLive()
	t0 := time.Unix(1_800_000_000, 0)
	k.NoteFix(nil, t0)
	k.NoteFix(&SolvedFixRecord{From: "!0000beef", Lat: 0, Lon: 0}, t0) // rejected
	k.NoteFix(&SolvedFixRecord{From: "!0000beef", Lat: 45.10, Lon: 9.10, UncertaintyM: 150, StationCount: 3, TimestampClass: "software_lock"}, t0)
	k.NoteFix(&SolvedFixRecord{From: "!0000beef", Lat: 45.11, Lon: 9.11, UncertaintyM: 90, StationCount: 4, TimestampClass: "software_lock", Degraded: true}, t0.Add(time.Second))
	doc := feedString(k, nil, t0.Add(time.Minute))
	kmlWellFormed(t, doc)
	for _, want := range []string{
		"0 node(s), 1 multilateration fix(es)",
		"<name>!0000beef (TDOA)</name>",
		"1-sigma uncertainty: 90 m",
		"Stations: 4",
		"software_lock (degraded)",
		"<name>1-sigma</name>",
		"<name>Fix trail</name>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestKML_Eviction(t *testing.T) {
	k := NewKMLLive()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < kmlMaxNodes+1; i++ {
		b := []byte(`{"from":"!` + strings.Repeat("0", 4) + hex4(i) + `","lat":10.5,"lon":20.5,"fields_trusted":true}`)
		k.NoteFrame(b, t0.Add(time.Duration(i)*time.Second))
	}
	if len(k.nodes) != kmlMaxNodes {
		t.Fatalf("nodes=%d want %d", len(k.nodes), kmlMaxNodes)
	}
	if _, ok := k.nodes["!00000000"]; ok {
		t.Fatalf("oldest node not evicted")
	}
}

func hex4(i int) string {
	const h = "0123456789abcdef"
	return string([]byte{h[i>>12&15], h[i>>8&15], h[i>>4&15], h[i&15]})
}

func TestKML_Handlers(t *testing.T) {
	// No token: link points at this host's feed, no token param.
	h := authWrap(kmlLinkHandler(7, ""), "")
	r := httptest.NewRequest(http.MethodGet, "http://10.0.0.9:9000/live.kml", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	kmlWellFormed(t, body)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/vnd.google-earth.kml+xml") {
		t.Errorf("content-type %q", ct)
	}
	if !strings.Contains(body, "<href>http://10.0.0.9:9000/live_feed.kml</href>") ||
		!strings.Contains(body, "<refreshInterval>7</refreshInterval>") {
		t.Errorf("network link:\n%s", body)
	}

	// Token set: unauthenticated request rejected; authenticated one
	// embeds the (escaped) token in the feed href.
	h = authWrap(kmlLinkHandler(10, "s3cr&t"), "s3cr&t")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/live.kml", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status=%d want 401", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://fusion.local/live.kml?token=s3cr%26t", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<href>http://fusion.local/live_feed.kml?token=s3cr%26t</href>") {
		t.Fatalf("token link status=%d:\n%s", w.Code, w.Body.String())
	}

	// Hostile Host header falls back to localhost.
	r = httptest.NewRequest(http.MethodGet, "/live.kml", nil)
	r.Host = `evil"><x>`
	w = httptest.NewRecorder()
	kmlLinkHandler(10, "").ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "<href>http://localhost/live_feed.kml</href>") {
		t.Errorf("hostile host not replaced:\n%s", w.Body.String())
	}

	// Feed handler renders registry sensors.
	reg := &Registry{byName: map[string]*Sensor{"roof": {Name: "roof", Lat: 45, Lon: 9}}}
	w = httptest.NewRecorder()
	kmlFeedHandler(NewKMLLive(), reg).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/live_feed.kml", nil))
	kmlWellFormed(t, w.Body.String())
	if !strings.Contains(w.Body.String(), "<name>roof</name>") {
		t.Errorf("registry sensor missing:\n%s", w.Body.String())
	}
}
