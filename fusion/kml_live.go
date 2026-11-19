// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/kml_live.go: live Google Earth KML feed for the fusion server.
//
// Same two-document layout as the per-sniffer /live.kml (and
// radiosonde_auto_rx):
//
//	GET /live.kml       -- NetworkLink only; Google Earth re-polls the
//	                       feed every --kml-refresh seconds.
//	GET /live_feed.kml  -- rebuilt from in-memory state per request.
//
// The feed is multi-station aware:
//
//	<Folder>Sensors</Folder>                 one placemark per station
//	<Folder>Nodes (self-reported)</Folder>   point + track per node, and
//	                                         a line from every station
//	                                         that heard it recently
//	<Folder>Multilateration fixes</Folder>   latest TDOA fix + 1-sigma
//	                                         circle + trail of fixes
//
// Only trusted frames (fields_trusted, or decrypted on older sniffers)
// feed positions and names, so CRC-failed phantoms never get plotted.
// Like /events, both routes sit behind --api-token; when a token is set
// the NetworkLink embeds it in the feed URL because Google Earth cannot
// send an Authorization header.

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	kmlMaxNodes     = 512
	kmlMaxNames     = 2048
	kmlTrackLen     = 64
	kmlFixTrailLen  = 32
	kmlStale        = time.Hour
	kmlHeardByFresh = 10 * time.Minute
	kmlMaxHeardBy   = 16
)

type kmlPoint struct {
	Lat, Lon, AltM float64
}

type kmlNode struct {
	ID       string
	HaveAlt  bool
	Track    []kmlPoint // oldest first, capped at kmlTrackLen
	Reports  int
	LastSeen time.Time
	Channel  string
	FreqHz   uint64
	HeardBy  map[string]kmlHeard // station -> latest reception
}

type kmlHeard struct {
	At    time.Time
	SnrDB float64
}

type kmlFix struct {
	ID       string
	Trail    []kmlPoint // oldest first, capped at kmlFixTrailLen
	UncM     float64
	Stations int
	Class    string
	Degraded bool
	At       time.Time
}

type kmlStation struct {
	Lat, Lon, AltM float64
	LastSeen       time.Time
}

// KMLLive is the fusion-side live-position cache. Safe for concurrent use.
type KMLLive struct {
	mu       sync.Mutex
	nodes    map[string]*kmlNode
	names    map[string]string
	fixes    map[string]*kmlFix
	stations map[string]*kmlStation
}

func NewKMLLive() *KMLLive {
	return &KMLLive{
		nodes:    map[string]*kmlNode{},
		names:    map[string]string{},
		fixes:    map[string]*kmlFix{},
		stations: map[string]*kmlStation{},
	}
}

// globalKML is fed by the main ingest loop and read by the web handlers.
var globalKML = NewKMLLive()

// kmlFrame is the subset of a sniffer JSON event the KML feed needs.
// Kept separate from Frame so adding these doesn't change what the TX
// consolidation path marshals.
type kmlFrame struct {
	Event         string   `json:"event"`
	From          string   `json:"from"`
	Station       string   `json:"station"`
	StationLat    float64  `json:"station_lat"`
	StationLon    float64  `json:"station_lon"`
	StationAltM   float64  `json:"station_alt_m"`
	Lat           *float64 `json:"lat"`
	Lon           *float64 `json:"lon"`
	AltM          *float64 `json:"alt_m"`
	LongName      string   `json:"long_name"`
	ShortName     string   `json:"short_name"`
	AtakCallsign  string   `json:"atak_callsign"`
	FieldsTrusted *bool    `json:"fields_trusted"`
	Decrypted     *bool    `json:"decrypted"`
	ChannelName   string   `json:"channel_name"`
	SnrDB         float64  `json:"snr_db"`
	FreqHz        uint64   `json:"freq_hz"`
}

func validLatLon(lat, lon float64) bool {
	if math.IsNaN(lat) || math.IsNaN(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return false
	}
	return !(lat == 0 && lon == 0) // (0,0) = "no GPS fix"
}

// NoteFrame ingests one raw sniffer JSON event.
func (k *KMLLive) NoteFrame(b []byte, now time.Time) {
	var f kmlFrame
	if err := json.Unmarshal(b, &f); err != nil || f.Event != "" || f.From == "" {
		return
	}
	trusted := false
	if f.FieldsTrusted != nil {
		trusted = *f.FieldsTrusted
	} else if f.Decrypted != nil {
		trusted = *f.Decrypted // pre-fields_trusted sniffers
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	// Station positions travel on every frame (gpsd) -- track them even
	// for untrusted frames; they come from our own sensor, not the air.
	if f.Station != "" && validLatLon(f.StationLat, f.StationLon) {
		st := k.stations[f.Station]
		if st == nil {
			st = &kmlStation{}
			k.stations[f.Station] = st
		}
		st.Lat, st.Lon, st.AltM, st.LastSeen = f.StationLat, f.StationLon, f.StationAltM, now
	}
	if !trusted {
		return
	}

	if name := firstNonEmpty(f.AtakCallsign, f.LongName); name != "" {
		if f.ShortName != "" && f.AtakCallsign == "" {
			name += " [" + f.ShortName + "]"
		}
		if _, ok := k.names[f.From]; ok || len(k.names) < kmlMaxNames {
			k.names[f.From] = name
		}
	}

	n := k.nodes[f.From]
	// A node with a position heard by a new station: record the
	// reception so the feed can draw station -> node lines.
	if n != nil && f.Station != "" {
		n.noteHeard(f.Station, f.SnrDB, now)
	}
	if f.Lat == nil || f.Lon == nil || !validLatLon(*f.Lat, *f.Lon) {
		return
	}
	if n == nil {
		if len(k.nodes) >= kmlMaxNodes {
			k.evictOldestNodeLocked()
		}
		n = &kmlNode{ID: f.From, HeardBy: map[string]kmlHeard{}}
		k.nodes[f.From] = n
		if f.Station != "" {
			n.noteHeard(f.Station, f.SnrDB, now)
		}
	}
	p := kmlPoint{Lat: *f.Lat, Lon: *f.Lon}
	n.HaveAlt = f.AltM != nil
	if n.HaveAlt {
		p.AltM = *f.AltM
	}
	if f.ChannelName != "" {
		n.Channel = f.ChannelName
	}
	if f.FreqHz != 0 {
		n.FreqHz = f.FreqHz
	}
	n.Reports++
	n.LastSeen = now
	// Several stations hear the same packet: only a moved position
	// extends the track.
	if len(n.Track) == 0 || n.Track[len(n.Track)-1] != p {
		n.Track = append(n.Track, p)
		if len(n.Track) > kmlTrackLen {
			n.Track = n.Track[len(n.Track)-kmlTrackLen:]
		}
	}
}

func (n *kmlNode) noteHeard(station string, snr float64, now time.Time) {
	if _, ok := n.HeardBy[station]; !ok && len(n.HeardBy) >= kmlMaxHeardBy {
		oldest, oldestAt := "", now
		for s, h := range n.HeardBy {
			if h.At.Before(oldestAt) || oldest == "" {
				oldest, oldestAt = s, h.At
			}
		}
		delete(n.HeardBy, oldest)
	}
	n.HeardBy[station] = kmlHeard{At: now, SnrDB: snr}
}

func (k *KMLLive) evictOldestNodeLocked() {
	var oldest *kmlNode
	for _, n := range k.nodes {
		if oldest == nil || n.LastSeen.Before(oldest.LastSeen) ||
			(n.LastSeen.Equal(oldest.LastSeen) && n.ID < oldest.ID) {
			oldest = n
		}
	}
	if oldest != nil {
		delete(k.nodes, oldest.ID)
	}
}

// NoteFix records a multilateration solution.
func (k *KMLLive) NoteFix(fix *SolvedFixRecord, now time.Time) {
	if fix == nil || fix.From == "" || !validLatLon(fix.Lat, fix.Lon) {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.fixes[fix.From]
	if f == nil {
		if len(k.fixes) >= kmlMaxNodes {
			var oldest *kmlFix
			for _, x := range k.fixes {
				if oldest == nil || x.At.Before(oldest.At) {
					oldest = x
				}
			}
			delete(k.fixes, oldest.ID)
		}
		f = &kmlFix{ID: fix.From}
		k.fixes[fix.From] = f
	}
	f.Trail = append(f.Trail, kmlPoint{Lat: fix.Lat, Lon: fix.Lon})
	if len(f.Trail) > kmlFixTrailLen {
		f.Trail = f.Trail[len(f.Trail)-kmlFixTrailLen:]
	}
	f.UncM, f.Stations, f.Class, f.Degraded, f.At = fix.UncertaintyM, fix.StationCount, fix.TimestampClass, fix.Degraded, now
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---- rendering ----

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// htmlDesc joins description lines with <br> after HTML-escaping each
// line, then XML-escapes the whole -- remote strings (node names,
// channel names) reach Google Earth's HTML renderer as text, not markup.
func htmlDesc(lines ...string) string {
	esc := make([]string, len(lines))
	for i, l := range lines {
		esc[i] = html.EscapeString(l)
	}
	return xmlText(strings.Join(esc, "<br>"))
}

func fmtAge(d time.Duration) string {
	s := int64(d / time.Second)
	switch {
	case s < 0:
		s = 0
		fallthrough
	case s < 120:
		return fmt.Sprintf("%ds ago", s)
	case s < 7200:
		return fmt.Sprintf("%dm ago", s/60)
	default:
		return fmt.Sprintf("%dh %dm ago", s/3600, (s%3600)/60)
	}
}

func coord(p kmlPoint) string { return fmt.Sprintf("%.6f,%.6f,%.1f", p.Lon, p.Lat, p.AltM) }

// circleRing approximates a radius-r circle (metres) around p as a
// closed 36-vertex ring, for the multilateration 1-sigma polygon.
func circleRing(p kmlPoint, r float64) string {
	const earthR = 6371000.0
	var b strings.Builder
	for i := 0; i <= 36; i++ {
		th := float64(i%36) * 2 * math.Pi / 36
		dLat := (r * math.Cos(th) / earthR) * 180 / math.Pi
		dLon := (r * math.Sin(th) / (earthR * math.Cos(p.Lat*math.Pi/180))) * 180 / math.Pi
		fmt.Fprintf(&b, "%.6f,%.6f,0 ", p.Lon+dLon, p.Lat+dLat)
	}
	return strings.TrimSpace(b.String())
}

const kmlFusionStyles = `  <Style id="node"><IconStyle><color>ff00ff00</color><scale>1.0</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon></IconStyle><LabelStyle><scale>0.85</scale></LabelStyle></Style>
  <Style id="node-stale"><IconStyle><color>ff9e9e9e</color><scale>0.8</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon></IconStyle><LabelStyle><color>ffbdbdbd</color><scale>0.7</scale></LabelStyle></Style>
  <Style id="track"><LineStyle><color>ff03bafc</color><width>2</width></LineStyle></Style>
  <Style id="heard"><LineStyle><color>80ffffff</color><width>1.5</width></LineStyle></Style>
  <Style id="station"><IconStyle><color>fff8bd38</color><scale>1.2</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/target.png</href></Icon></IconStyle></Style>
  <Style id="fix"><IconStyle><color>ffff00ff</color><scale>1.1</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/open-diamond.png</href></Icon></IconStyle><LabelStyle><color>ffff00ff</color><scale>0.85</scale></LabelStyle></Style>
  <Style id="fix-ring"><LineStyle><color>ccff00ff</color><width>1.5</width></LineStyle><PolyStyle><color>33ff00ff</color></PolyStyle></Style>
  <Style id="fix-trail"><LineStyle><color>99ff00ff</color><width>1.5</width></LineStyle></Style>
`

// WriteKMLNetworkLink writes the /live.kml document.
func WriteKMLNetworkLink(w io.Writer, feedURL string, refreshS int) {
	if refreshS < 1 {
		refreshS = 1
	}
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <NetworkLink>
    <name>Meshtastic fusion live positions</name>
    <open>1</open>
    <Link>
      <href>%s</href>
      <refreshMode>onInterval</refreshMode>
      <refreshInterval>%d</refreshInterval>
    </Link>
  </NetworkLink>
</Document>
</kml>
`, xmlText(feedURL), refreshS)
}

// WriteFeed writes the /live_feed.kml document. sensors supplies the
// registry's configured positions; live gpsd positions from frames win.
func (k *KMLLive) WriteFeed(w io.Writer, sensors []Sensor, now time.Time) {
	k.mu.Lock()
	type stationOut struct {
		Name string
		kmlStation
		live bool
	}
	stations := map[string]stationOut{}
	for _, s := range sensors {
		if validLatLon(s.Lat, s.Lon) {
			stations[s.Name] = stationOut{Name: s.Name, kmlStation: kmlStation{Lat: s.Lat, Lon: s.Lon, AltM: s.AltM}}
		}
	}
	for name, st := range k.stations {
		stations[name] = stationOut{Name: name, kmlStation: *st, live: true}
	}
	nodes := make([]kmlNode, 0, len(k.nodes))
	for _, n := range k.nodes {
		c := *n
		c.Track = append([]kmlPoint(nil), n.Track...)
		c.HeardBy = make(map[string]kmlHeard, len(n.HeardBy))
		for s, h := range n.HeardBy {
			c.HeardBy[s] = h
		}
		nodes = append(nodes, c)
	}
	fixes := make([]kmlFix, 0, len(k.fixes))
	for _, f := range k.fixes {
		c := *f
		c.Trail = append([]kmlPoint(nil), f.Trail...)
		fixes = append(fixes, c)
	}
	names := make(map[string]string, len(nodes)+len(fixes))
	for _, n := range nodes {
		names[n.ID] = k.names[n.ID]
	}
	for _, f := range fixes {
		names[f.ID] = k.names[f.ID]
	}
	k.mu.Unlock()

	sort.Slice(nodes, func(i, j int) bool {
		if !nodes[i].LastSeen.Equal(nodes[j].LastSeen) {
			return nodes[i].LastSeen.After(nodes[j].LastSeen)
		}
		return nodes[i].ID < nodes[j].ID
	})
	sort.Slice(fixes, func(i, j int) bool {
		if !fixes[i].At.Equal(fixes[j].At) {
			return fixes[i].At.After(fixes[j].At)
		}
		return fixes[i].ID < fixes[j].ID
	})
	stNames := make([]string, 0, len(stations))
	for n := range stations {
		stNames = append(stNames, n)
	}
	sort.Strings(stNames)

	label := func(id string) string {
		if names[id] != "" {
			return names[id]
		}
		return id
	}

	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <name>meshtastic-fusion</name>
  <open>1</open>
  <description>%d sensor(s), %d node(s), %d multilateration fix(es). Generated %s.</description>
%s`, len(stations), len(nodes), len(fixes), now.UTC().Format(time.RFC3339), kmlFusionStyles)

	fmt.Fprintf(w, "  <Folder>\n    <name>Sensors</name>\n    <open>0</open>\n")
	for _, name := range stNames {
		st := stations[name]
		src := "configured position (sensor registry)"
		if st.live {
			src = "gpsd position, last reported " + fmtAge(now.Sub(st.LastSeen))
		}
		fmt.Fprintf(w, "    <Placemark>\n      <name>%s</name>\n      <description>%s</description>\n      <styleUrl>#station</styleUrl>\n      <Point><altitudeMode>absolute</altitudeMode><coordinates>%s</coordinates></Point>\n    </Placemark>\n",
			xmlText(name), htmlDesc("Sensor: "+name, src), coord(kmlPoint{st.Lat, st.Lon, st.AltM}))
	}
	fmt.Fprintf(w, "  </Folder>\n")

	fmt.Fprintf(w, "  <Folder>\n    <name>Nodes (self-reported)</name>\n    <open>1</open>\n")
	for _, n := range nodes {
		cur := n.Track[len(n.Track)-1]
		altMode := "clampToGround"
		if n.HaveAlt {
			altMode = "absolute"
		}
		style := "node"
		if now.Sub(n.LastSeen) > kmlStale {
			style = "node-stale"
		}
		lines := []string{
			"Node: " + n.ID,
			fmt.Sprintf("Last heard: %s (%s)", n.LastSeen.UTC().Format(time.RFC3339), fmtAge(now.Sub(n.LastSeen))),
			fmt.Sprintf("Position: %.6f, %.6f", cur.Lat, cur.Lon),
		}
		if n.HaveAlt {
			lines = append(lines, fmt.Sprintf("Altitude: %.0f m", cur.AltM))
		}
		if n.Channel != "" {
			lines = append(lines, "Channel: "+n.Channel)
		}
		if n.FreqHz != 0 {
			lines = append(lines, fmt.Sprintf("Frequency: %.3f MHz", float64(n.FreqHz)/1e6))
		}
		heard := make([]string, 0, len(n.HeardBy))
		for s := range n.HeardBy {
			heard = append(heard, s)
		}
		sort.Strings(heard)
		for _, s := range heard {
			h := n.HeardBy[s]
			lines = append(lines, fmt.Sprintf("Heard by %s: SNR %.1f dB, %s", s, h.SnrDB, fmtAge(now.Sub(h.At))))
		}
		lines = append(lines, fmt.Sprintf("Position reports: %d, track points: %d", n.Reports, len(n.Track)))

		fmt.Fprintf(w, "    <Folder>\n      <name>%s</name>\n      <open>0</open>\n", xmlText(label(n.ID)))
		fmt.Fprintf(w, "      <Placemark>\n        <name>%s</name>\n        <styleUrl>#%s</styleUrl>\n        <description>%s</description>\n        <Point><altitudeMode>%s</altitudeMode><coordinates>%s</coordinates></Point>\n      </Placemark>\n",
			xmlText(label(n.ID)), style, htmlDesc(lines...), altMode, coord(cur))
		if len(n.Track) >= 2 {
			fmt.Fprintf(w, "      <Placemark>\n        <name>Track</name>\n        <styleUrl>#track</styleUrl>\n        <LineString><tessellate>1</tessellate><altitudeMode>%s</altitudeMode><coordinates>\n", altMode)
			for _, p := range n.Track {
				fmt.Fprintf(w, "          %s\n", coord(p))
			}
			fmt.Fprintf(w, "        </coordinates></LineString>\n      </Placemark>\n")
		}
		for _, s := range heard {
			st, ok := stations[s]
			if !ok || now.Sub(n.HeardBy[s].At) > kmlHeardByFresh {
				continue
			}
			fmt.Fprintf(w, "      <Placemark>\n        <name>%s</name>\n        <styleUrl>#heard</styleUrl>\n        <LineString><tessellate>1</tessellate><altitudeMode>clampToGround</altitudeMode><coordinates>%s %s</coordinates></LineString>\n      </Placemark>\n",
				xmlText("Heard by "+s), coord(kmlPoint{st.Lat, st.Lon, 0}), coord(kmlPoint{cur.Lat, cur.Lon, 0}))
		}
		fmt.Fprintf(w, "    </Folder>\n")
	}
	fmt.Fprintf(w, "  </Folder>\n")

	fmt.Fprintf(w, "  <Folder>\n    <name>Multilateration fixes</name>\n    <open>1</open>\n")
	for _, f := range fixes {
		cur := f.Trail[len(f.Trail)-1]
		lines := []string{
			"Node: " + f.ID,
			fmt.Sprintf("Solved: %s (%s)", f.At.UTC().Format(time.RFC3339), fmtAge(now.Sub(f.At))),
			fmt.Sprintf("Position: %.6f, %.6f", cur.Lat, cur.Lon),
			fmt.Sprintf("1-sigma uncertainty: %.0f m", f.UncM),
			fmt.Sprintf("Stations: %d", f.Stations),
		}
		if f.Class != "" {
			cls := "Timestamp class: " + f.Class
			if f.Degraded {
				cls += " (degraded)"
			}
			lines = append(lines, cls)
		}
		name := label(f.ID) + " (TDOA)"
		fmt.Fprintf(w, "    <Folder>\n      <name>%s</name>\n      <open>0</open>\n", xmlText(name))
		fmt.Fprintf(w, "      <Placemark>\n        <name>%s</name>\n        <styleUrl>#fix</styleUrl>\n        <description>%s</description>\n        <Point><coordinates>%s</coordinates></Point>\n      </Placemark>\n",
			xmlText(name), htmlDesc(lines...), coord(cur))
		if f.UncM > 0 {
			fmt.Fprintf(w, "      <Placemark>\n        <name>1-sigma</name>\n        <styleUrl>#fix-ring</styleUrl>\n        <Polygon><tessellate>1</tessellate><outerBoundaryIs><LinearRing><coordinates>%s</coordinates></LinearRing></outerBoundaryIs></Polygon>\n      </Placemark>\n",
				circleRing(cur, f.UncM))
		}
		if len(f.Trail) >= 2 {
			fmt.Fprintf(w, "      <Placemark>\n        <name>Fix trail</name>\n        <styleUrl>#fix-trail</styleUrl>\n        <LineString><tessellate>1</tessellate><coordinates>\n")
			for _, p := range f.Trail {
				fmt.Fprintf(w, "          %s\n", coord(p))
			}
			fmt.Fprintf(w, "        </coordinates></LineString>\n      </Placemark>\n")
		}
		fmt.Fprintf(w, "    </Folder>\n")
	}
	fmt.Fprintf(w, "  </Folder>\n</Document>\n</kml>\n")
}

// validHost accepts host[:port] made of letters, digits and . - : [ ].
func validHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

const kmlContentType = "application/vnd.google-earth.kml+xml; charset=utf-8"

// kmlLinkHandler serves /live.kml. apiToken, when set, is appended to
// the feed URL: the request already passed authWrap, and Google Earth
// has no way to send the bearer header on its refresh polls.
func kmlLinkHandler(refreshS int, apiToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if !validHost(host) {
			host = "localhost"
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		feed := scheme + "://" + host + "/live_feed.kml"
		if apiToken != "" {
			feed += "?token=" + url.QueryEscape(apiToken)
		}
		w.Header().Set("Content-Type", kmlContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", `attachment; filename="meshtastic-fusion-live.kml"`)
		WriteKMLNetworkLink(w, feed, refreshS)
	}
}

// kmlFeedHandler serves /live_feed.kml.
func kmlFeedHandler(k *KMLLive, registry *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sensors []Sensor
		if registry != nil {
			sensors = registry.List()
		}
		w.Header().Set("Content-Type", kmlContentType)
		w.Header().Set("Cache-Control", "no-store")
		k.WriteFeed(w, sensors, time.Now())
	}
}
