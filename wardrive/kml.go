// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/kml.go: KML output for Google Earth / ATAK / GIS viewers.
//
// Document layout:
//
//	<Document>
//	  styles for: decrypted, encrypted, router, track, confidence
//	  <Folder>Operator path</Folder>      -- gx:Track from TrackPoints
//	  <Folder>Meshtastic nodes</Folder>
//	    <Folder>Decrypted (channel known)</Folder>
//	    <Folder>Encrypted (channel unknown)</Folder>
//	    <Folder>Confidence circles</Folder>  -- per-node 1-sigma rings
//
// Each node Placemark has a description CDATA block summarizing
// observations + estimate metadata. The pin location is the node's
// EstLat/EstLon (centroid or self-reported).
//
// We intentionally do NOT use html/template here -- KML is a small
// closed schema and a hand-rolled writer keeps the output diff-stable
// across Go versions (template iteration order can churn).

package main

import (
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

const kmlTimeFormat = "2006-01-02T15:04:05Z"

// kmlStyles is the inline <Style> block embedded in every Document.
// Colors use KML's AABBGGRR encoding (alpha first). Picked to read
// well on the dark Carto basemap while still being legible on
// Google Earth's default imagery.
const kmlStyles = `<Style id="mesh-decrypted">
  <IconStyle><color>ff00ff00</color><scale>1.1</scale><Icon><href>http://maps.google.com/mapfiles/kml/paddle/grn-circle.png</href></Icon></IconStyle>
  <LabelStyle><color>ff00ff00</color><scale>0.85</scale></LabelStyle>
</Style>
<Style id="mesh-encrypted">
  <IconStyle><color>ff00aaff</color><scale>1.0</scale><Icon><href>http://maps.google.com/mapfiles/kml/paddle/orange-circle.png</href></Icon></IconStyle>
  <LabelStyle><color>ff00aaff</color><scale>0.8</scale></LabelStyle>
</Style>
<Style id="mesh-router">
  <IconStyle><color>ffff00ff</color><scale>1.2</scale><Icon><href>http://maps.google.com/mapfiles/kml/paddle/purple-stars.png</href></Icon></IconStyle>
  <LabelStyle><color>ffff00ff</color><scale>0.9</scale></LabelStyle>
</Style>
<Style id="mesh-track">
  <LineStyle><color>ffffff00</color><width>3</width></LineStyle>
</Style>
<Style id="mesh-confidence-decrypted">
  <LineStyle><color>4400ff00</color><width>1</width></LineStyle>
  <PolyStyle><color>2200ff00</color><fill>1</fill><outline>1</outline></PolyStyle>
</Style>
<Style id="mesh-confidence-encrypted">
  <LineStyle><color>4400aaff</color><width>1</width></LineStyle>
  <PolyStyle><color>2200aaff</color><fill>1</fill><outline>1</outline></PolyStyle>
</Style>`

// roleRouter is the Meshtastic protobuf enum value for role=ROUTER.
// Defined locally so this file doesn't pull a dependency on the
// firmware protobufs; kept in sync via a single named constant.
const roleRouter uint32 = 2

// WriteKML serializes a session's observations + tracks to KML.
func WriteKML(w io.Writer, sess Session, aggs []*NodeAggregate, track []TrackPoint) error {
	fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintln(w, `<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2">`)
	fmt.Fprintln(w, `<Document>`)
	docName := documentName(sess)
	fmt.Fprintf(w, "  <name>%s</name>\n", xmlEscape(docName))
	fmt.Fprintf(w, "  <description>%s</description>\n", xmlEscape(documentDescription(sess, aggs, track)))
	fmt.Fprintln(w, kmlStyles)

	// Operator path
	if len(track) > 0 {
		fmt.Fprintln(w, `  <Folder><name>Operator path</name>`)
		fmt.Fprintln(w, `    <Placemark><name>track</name><styleUrl>#mesh-track</styleUrl>`)
		fmt.Fprintln(w, `      <gx:Track>`)
		for _, tp := range track {
			fmt.Fprintf(w, "        <when>%s</when>\n", tp.TS.UTC().Format(kmlTimeFormat))
		}
		for _, tp := range track {
			fmt.Fprintf(w, "        <gx:coord>%.7f %.7f %.2f</gx:coord>\n",
				tp.Lon, tp.Lat, tp.AltM)
		}
		fmt.Fprintln(w, `      </gx:Track>`)
		fmt.Fprintln(w, `    </Placemark>`)
		fmt.Fprintln(w, `  </Folder>`)
	}

	// Nodes -- decrypted first, then encrypted-only, then confidence rings.
	fmt.Fprintln(w, `  <Folder><name>Meshtastic nodes</name>`)

	fmt.Fprintln(w, `    <Folder><name>Decrypted (channel known)</name>`)
	for _, a := range aggs {
		if a.ChannelName == "" {
			continue
		}
		writeNodePlacemark(w, a)
	}
	fmt.Fprintln(w, `    </Folder>`)

	fmt.Fprintln(w, `    <Folder><name>Encrypted (channel unknown)</name>`)
	for _, a := range aggs {
		if a.ChannelName != "" {
			continue
		}
		writeNodePlacemark(w, a)
	}
	fmt.Fprintln(w, `    </Folder>`)

	fmt.Fprintln(w, `    <Folder><name>Confidence circles</name>`)
	for _, a := range aggs {
		if a.EstUncertaintyM <= 0 {
			continue
		}
		writeConfidenceRing(w, a)
	}
	fmt.Fprintln(w, `    </Folder>`)

	fmt.Fprintln(w, `  </Folder>`)
	fmt.Fprintln(w, `</Document>`)
	fmt.Fprintln(w, `</kml>`)
	return nil
}

func writeNodePlacemark(w io.Writer, a *NodeAggregate) {
	style := "#mesh-encrypted"
	if a.ChannelName != "" {
		style = "#mesh-decrypted"
	}
	if a.Role == roleRouter {
		style = "#mesh-router"
	}
	fmt.Fprintln(w, `      <Placemark>`)
	fmt.Fprintf(w, "        <name>%s</name>\n", xmlEscape(nodeDisplayName(a)))
	fmt.Fprintf(w, "        <styleUrl>%s</styleUrl>\n", style)
	fmt.Fprintf(w, "        <description><![CDATA[%s]]></description>\n", nodeDescriptionHTML(a))
	fmt.Fprintf(w, "        <Point><coordinates>%.7f,%.7f,0</coordinates></Point>\n", a.EstLon, a.EstLat)
	fmt.Fprintln(w, `      </Placemark>`)
}

func writeConfidenceRing(w io.Writer, a *NodeAggregate) {
	style := "#mesh-confidence-encrypted"
	if a.ChannelName != "" {
		style = "#mesh-confidence-decrypted"
	}
	pts := circlePoints(a.EstLat, a.EstLon, a.EstUncertaintyM, 32)
	fmt.Fprintln(w, `      <Placemark>`)
	fmt.Fprintf(w, "        <name>%s 1-sigma</name>\n", xmlEscape(a.NodeID))
	fmt.Fprintf(w, "        <styleUrl>%s</styleUrl>\n", style)
	fmt.Fprintln(w, `        <Polygon><outerBoundaryIs><LinearRing><coordinates>`)
	for _, p := range pts {
		fmt.Fprintf(w, "          %.7f,%.7f,0\n", p[1], p[0]) // lon,lat
	}
	fmt.Fprintln(w, `        </coordinates></LinearRing></outerBoundaryIs></Polygon>`)
	fmt.Fprintln(w, `      </Placemark>`)
}

// circlePoints returns N points on a great-circle ring of `radiusM`
// meters around (lat, lon). Closed (last point == first point) so a
// KML <LinearRing> renders cleanly.
func circlePoints(lat, lon, radiusM float64, n int) [][2]float64 {
	out := make([][2]float64, 0, n+1)
	if n < 3 {
		n = 32
	}
	angRad := radiusM / EarthRadiusM // angular radius in radians
	latRad := lat * math.Pi / 180.0
	lonRad := lon * math.Pi / 180.0
	for i := 0; i <= n; i++ {
		theta := float64(i) * 2.0 * math.Pi / float64(n)
		bearing := theta
		sinLat := math.Sin(latRad)*math.Cos(angRad) +
			math.Cos(latRad)*math.Sin(angRad)*math.Cos(bearing)
		newLat := math.Asin(sinLat)
		y := math.Sin(bearing) * math.Sin(angRad) * math.Cos(latRad)
		x := math.Cos(angRad) - math.Sin(latRad)*sinLat
		newLon := lonRad + math.Atan2(y, x)
		out = append(out, [2]float64{
			newLat * 180.0 / math.Pi,
			newLon * 180.0 / math.Pi,
		})
	}
	return out
}

func nodeDisplayName(a *NodeAggregate) string {
	if a.LongName != "" {
		if a.ShortName != "" {
			return fmt.Sprintf("%s %s [%s]", a.NodeID, a.LongName, a.ShortName)
		}
		return fmt.Sprintf("%s %s", a.NodeID, a.LongName)
	}
	return a.NodeID
}

func nodeDescriptionHTML(a *NodeAggregate) string {
	var sb strings.Builder
	sb.WriteString("<table>")
	row := func(k, v string) {
		fmt.Fprintf(&sb, "<tr><td><b>%s</b></td><td>%s</td></tr>", xmlEscape(k), xmlEscape(v))
	}
	row("Node id", a.NodeID)
	if a.LongName != "" {
		row("Long name", a.LongName)
	}
	if a.ShortName != "" {
		row("Short name", a.ShortName)
	}
	if a.HWModel != 0 {
		row("HW model", fmt.Sprintf("%d", a.HWModel))
	}
	if a.Role != 0 {
		row("Role", fmt.Sprintf("%d", a.Role))
	}
	if a.ChannelName != "" {
		row("Channel", a.ChannelName)
	}
	row("Channel hash", fmt.Sprintf("0x%02x", a.ChannelHash))
	if a.Preset != "" {
		row("Preset", a.Preset)
	}
	if a.FreqHz != 0 {
		row("Frequency", fmt.Sprintf("%.3f MHz", float64(a.FreqHz)/1e6))
	}
	row("First seen (UTC)", a.FirstSeen.UTC().Format(kmlTimeFormat))
	row("Last seen (UTC)", a.LastSeen.UTC().Format(kmlTimeFormat))
	row("Observations", fmt.Sprintf("%d", a.ObsCount))
	row("Best RSSI", fmt.Sprintf("%.1f dBm", a.BestRSSIdBm))
	if a.BestSNRdB != 0 {
		row("Best SNR", fmt.Sprintf("%.1f dB", a.BestSNRdB))
	}
	row("Estimate", fmt.Sprintf("%.7f, %.7f (%s, ~%.0f m 1-sigma)",
		a.EstLat, a.EstLon, a.EstMethod, a.EstUncertaintyM))
	if a.SelfReportedTS != nil {
		row("Self-reported", fmt.Sprintf("%.7f, %.7f at %s",
			a.SelfReportedLat, a.SelfReportedLon,
			a.SelfReportedTS.UTC().Format(kmlTimeFormat)))
	}
	sb.WriteString("</table>")
	sb.WriteString("<p><i>Confidence radius is the RSSI&sup2;-weighted spread of observations from the centroid; ")
	sb.WriteString("it is a measure of consistency with the data, not a guarantee that the emitter sits within the ring.</i></p>")
	return sb.String()
}

func documentName(sess Session) string {
	stationPart := sess.StationID
	if stationPart == "" {
		stationPart = "wardrive"
	}
	return fmt.Sprintf("meshtastic-wardrive: %s %s",
		stationPart, sess.StartTS.UTC().Format("2006-01-02"))
}

func documentDescription(sess Session, aggs []*NodeAggregate, track []TrackPoint) string {
	dec, enc := 0, 0
	for _, a := range aggs {
		if a.ChannelName != "" {
			dec++
		} else {
			enc++
		}
	}
	dur := time.Duration(0)
	if !sess.EndTS.IsZero() {
		dur = sess.EndTS.Sub(sess.StartTS)
	}
	return fmt.Sprintf(
		"%s session %s. %d nodes (%d decrypted, %d encrypted-only) over %d GPS fixes; duration %s.",
		AppName, sess.SessionID, len(aggs), dec, enc, len(track), dur.Round(time.Second))
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
