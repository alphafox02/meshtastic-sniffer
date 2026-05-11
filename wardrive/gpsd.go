// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/gpsd.go: TCP/JSON client for gpsd.
//
// Mirrors the sniffer's gpsd.c (?WATCH={"enable":true,"json":true},
// parse TPV reports, prefer altMSL over alt) and adds parsing for
// epx/epy/eph so the AccuracyMeters field on every observation can
// reflect actual GPS uncertainty rather than the hardcoded zero
// Kismet's writer uses.
//
// Maintains a single shared "current fix" protected by a mutex; the
// capture path reads it on every observation and the tracks writer
// reads it on a decimated cadence.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// GPSFix is the gpsd-reported state at one moment in time. Lat/Lon
// are zero when no fix is current; callers check Valid before using
// the coordinates.
type GPSFix struct {
	Valid       bool
	TS          time.Time
	Lat         float64
	Lon         float64
	AltM        float64
	SpeedMps    float64
	HeadingDeg  float64
	AccuracyM   float64 // worst-of(epx, epy) approximation of 1-sigma horizontal
	HDOP        float64
	Sats        int
}

// GPSDClient connects to gpsd, reads TPV reports, and exposes the
// most-recent fix via Current(). Reconnects with backoff on failure.
type GPSDClient struct {
	endpoint string

	mu      sync.RWMutex
	current GPSFix
	// LastUpdate tracks wall-clock receipt time, separate from the
	// gpsd-reported TS field, so a stale connection (no TPVs for
	// minutes) can be detected even if a stuck device keeps repeating
	// its last timestamp.
	lastUpdate time.Time
}

// NewGPSDClient configures a client. endpoint accepts "host",
// "host:port", or ":port"; missing host defaults to localhost,
// missing port to 2947 (gpsd's default).
func NewGPSDClient(endpoint string) *GPSDClient {
	return &GPSDClient{endpoint: endpoint}
}

// Run blocks until ctx is cancelled, repeatedly connecting to gpsd
// and consuming TPV reports. Logs once per connection state change.
func (c *GPSDClient) Run(ctx context.Context) {
	host, port := parseGPSDEndpoint(c.endpoint)
	announced := false
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
		if err != nil {
			if !announced {
				log.Printf("gpsd: cannot connect to %s:%d (will retry): %v", host, port, err)
				announced = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		log.Printf("gpsd: connected to %s:%d", host, port)
		announced = false
		c.readLoop(ctx, conn)
		_ = conn.Close()
		// Loop and reconnect.
	}
}

func (c *GPSDClient) readLoop(ctx context.Context, conn net.Conn) {
	// Subscribe to JSON-mode TPV reports. Match the C client.
	if _, err := conn.Write([]byte("?WATCH={\"enable\":true,\"json\":true}\n")); err != nil {
		log.Printf("gpsd: write watch: %v", err)
		return
	}
	// gpsd line-buffers reports at newline boundaries; bufio.Scanner
	// handles that.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 8192), 65536)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return
		}
		line := scanner.Bytes()
		c.parseTPV(line)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("gpsd: read: %v", err)
	}
}

// tpvReport is the subset of gpsd's TPV class we consume. Unknown
// fields are tolerated by encoding/json's default behavior.
type tpvReport struct {
	Class   string  `json:"class"`
	Mode    int     `json:"mode"`
	Time    string  `json:"time,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
	Alt     float64 `json:"alt,omitempty"`
	AltMSL  float64 `json:"altMSL,omitempty"`
	Speed   float64 `json:"speed,omitempty"`
	Track   float64 `json:"track,omitempty"`
	Epx     float64 `json:"epx,omitempty"`
	Epy     float64 `json:"epy,omitempty"`
	Eph     float64 `json:"eph,omitempty"`
	Sats    int     `json:"satellites_used,omitempty"`
}

func (c *GPSDClient) parseTPV(line []byte) {
	// Cheap pre-filter: ignore lines that aren't TPV class. Saves
	// json.Unmarshal cost on every SKY/ATT/DEVICES/VERSION line.
	if !bytesContains(line, []byte(`"class":"TPV"`)) {
		return
	}
	var r tpvReport
	if err := json.Unmarshal(line, &r); err != nil {
		return
	}
	if r.Mode < 2 || r.Lat == 0 && r.Lon == 0 {
		return
	}
	fix := GPSFix{
		Valid:      true,
		Lat:        r.Lat,
		Lon:        r.Lon,
		SpeedMps:   r.Speed,
		HeadingDeg: r.Track,
		HDOP:       r.Eph,
		Sats:       r.Sats,
	}
	// Prefer altMSL over alt; matches the C client and what an
	// operator-friendly Z value should be.
	if r.AltMSL != 0 {
		fix.AltM = r.AltMSL
	} else {
		fix.AltM = r.Alt
	}
	// AccuracyM = max(epx, epy) when both present (worst-of for
	// horizontal); else use eph if present.
	if r.Epx > 0 || r.Epy > 0 {
		fix.AccuracyM = r.Epx
		if r.Epy > fix.AccuracyM {
			fix.AccuracyM = r.Epy
		}
	} else if r.Eph > 0 {
		fix.AccuracyM = r.Eph
	}
	// Parse the gpsd TS (RFC3339); ignore parse errors -- fall back
	// to wall-clock at receipt.
	if r.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.Time); err == nil {
			fix.TS = t.UTC()
		}
	}
	if fix.TS.IsZero() {
		fix.TS = time.Now().UTC()
	}

	c.mu.Lock()
	c.current = fix
	c.lastUpdate = time.Now()
	c.mu.Unlock()
}

// Current returns the most-recent fix. The returned GPSFix is a
// value copy; safe to read without holding the client's lock.
// Returns Valid=false until the first TPV arrives.
func (c *GPSDClient) Current() GPSFix {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Stale-fix guard: if the last update is more than 30 s old, the
	// fix is no longer trustworthy (vehicle entered a tunnel, gpsd
	// died, etc.). Surface that to callers via Valid=false rather
	// than silently feeding stale coords into observations.
	if !c.current.Valid {
		return c.current
	}
	if !c.lastUpdate.IsZero() && time.Since(c.lastUpdate) > 30*time.Second {
		stale := c.current
		stale.Valid = false
		return stale
	}
	return c.current
}

// parseGPSDEndpoint handles "host", "host:port", or ":port" forms.
func parseGPSDEndpoint(endpoint string) (host string, port int) {
	host, port = "localhost", 2947
	if endpoint == "" {
		return
	}
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		if i > 0 {
			host = endpoint[:i]
		}
		var p int
		fmt.Sscanf(endpoint[i+1:], "%d", &p)
		if p > 0 && p < 65536 {
			port = p
		}
	} else {
		host = endpoint
	}
	return
}

// bytesContains is the byte-slice equivalent of strings.Contains.
// Inlined here to avoid pulling bytes for one call.
func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
