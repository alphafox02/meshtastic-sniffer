// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/csv.go: native Meshtastic-flavored CSV emitter.
//
// Two CSV shapes are produced:
//
//   "aggregated" -- one row per node. The export most users will look
//                   at and what gets mailed to WiGLE for review. File
//                   begins with a key=value preamble line tagging the
//                   format version, app, sdr, region, station, and
//                   session id. Then a header row, then data rows.
//
//   "raw"        -- one row per observation. Full-fidelity dump for
//                   downstream analysis (path-loss fitting, custom
//                   re-estimation, etc.). Same preamble shape.
//
// Both forms use stdlib encoding/csv with default RFC 4180 quoting.
// Timestamps render as ISO-8601 UTC with second precision.

package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const csvTimeFormat = "2006-01-02T15:04:05Z"

// PreambleLine builds the human-readable descriptor line that goes
// at the top of any wardrive CSV. Parallel in shape to WigleWifi-1.6's
// preamble so anyone familiar with the wardriving ecosystem
// recognizes the shape on sight.
//
// Example:
//
//	MeshtasticWardrive-1.0,appRelease=meshtastic-wardrive-1.0.0,sdr=hackrf,region=US,station=mobile-rx,session_id=1
//
// The preamble is comma-separated key=value pairs. Commas inside a
// value are replaced with ';' so a naive split-on-comma parser still
// recovers the right pair count (e.g. presets=LongFast;MediumFast).
func PreambleLine(s Session) string {
	parts := []string{
		FormatVersion,
		"appRelease=" + sanitizePreambleValue(s.AppRelease),
	}
	if s.SDR != "" {
		parts = append(parts, "sdr="+sanitizePreambleValue(s.SDR))
	}
	if s.Region != "" {
		parts = append(parts, "region="+sanitizePreambleValue(s.Region))
	}
	if s.Presets != "" {
		parts = append(parts, "presets="+sanitizePreambleValue(s.Presets))
	}
	if s.StationID != "" {
		parts = append(parts, "station="+sanitizePreambleValue(s.StationID))
	}
	if s.SessionID != "" {
		parts = append(parts, "session_id="+sanitizePreambleValue(s.SessionID))
	}
	return strings.Join(parts, ",")
}

// sanitizePreambleValue replaces structural characters in a preamble
// value so a naive parser can still split key=value pairs by ','. We
// substitute ',' with ';' (typical multi-value separator) and '=' with
// '_' to keep the key= boundary unambiguous.
func sanitizePreambleValue(v string) string {
	r := strings.NewReplacer(",", ";", "=", "_", "\n", " ", "\r", " ")
	return r.Replace(v)
}

// AggregatedCSVHeader names the columns of the aggregated form.
// Order is documented as part of the format; new columns append at
// the end so older parsers can still index by-position.
var AggregatedCSVHeader = []string{
	"node_id",
	"long_name",
	"short_name",
	"hw_model",
	"role",
	"channel_name",
	"channel_hash",
	"preset",
	"bw_hz",
	"freq_hz",
	"first_seen_utc",
	"last_seen_utc",
	"obs_count",
	"best_rssi_dbm",
	"best_rssi_ts_utc",
	"best_snr_db",
	"est_lat",
	"est_lon",
	"est_uncertainty_m",
	"est_method",
	"selfrep_lat",
	"selfrep_lon",
	"selfrep_alt_m",
	"selfrep_ts_utc",
	"session_id",
	"station_id",
}

// WriteAggregatedCSV emits the aggregated form to `w`. Returns any
// IO or csv-encoding error encountered.
func WriteAggregatedCSV(w io.Writer, sess Session, aggs []*NodeAggregate) error {
	if _, err := fmt.Fprintln(w, PreambleLine(sess)); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(AggregatedCSVHeader); err != nil {
		return err
	}
	for _, a := range aggs {
		row := []string{
			a.NodeID,
			a.LongName,
			a.ShortName,
			fmtUint(uint64(a.HWModel)),
			fmtUint(uint64(a.Role)),
			a.ChannelName,
			fmt.Sprintf("0x%02x", a.ChannelHash),
			a.Preset,
			fmtUint(uint64(a.BWHz)),
			fmtUint(a.FreqHz),
			a.FirstSeen.UTC().Format(csvTimeFormat),
			a.LastSeen.UTC().Format(csvTimeFormat),
			strconv.Itoa(a.ObsCount),
			fmtFloat(a.BestRSSIdBm, 1),
			a.BestRSSITS.UTC().Format(csvTimeFormat),
			fmtFloat(a.BestSNRdB, 2),
			fmtFloat(a.EstLat, 7),
			fmtFloat(a.EstLon, 7),
			fmtFloat(a.EstUncertaintyM, 1),
			a.EstMethod,
			fmtFloatOrEmpty(a.SelfReportedLat, 7),
			fmtFloatOrEmpty(a.SelfReportedLon, 7),
			fmtFloatOrEmpty(a.SelfReportedAltM, 2),
			fmtTimePtr(a.SelfReportedTS),
			a.SessionID,
			a.StationID,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// RawCSVHeader names the columns of the raw observation form.
var RawCSVHeader = []string{
	"ts_utc",
	"node_id",
	"packet_id",
	"rx_lat",
	"rx_lon",
	"rx_alt_m",
	"rx_speed_mps",
	"rx_heading_deg",
	"hdop",
	"sats",
	"rssi_dbm",
	"snr_db",
	"freq_hz",
	"bw_hz",
	"preset",
	"channel_hash",
	"channel_name",
	"decrypted",
	"port_name",
	"payload_crc_ok",
	"hop_limit",
	"hop_start",
}

// WriteRawCSV emits the raw observation form to `w`.
func WriteRawCSV(w io.Writer, sess Session, obs []Observation) error {
	if _, err := fmt.Fprintln(w, PreambleLine(sess)); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(RawCSVHeader); err != nil {
		return err
	}
	for _, o := range obs {
		row := []string{
			o.TS.UTC().Format(csvTimeFormat),
			o.NodeID,
			fmtUint(uint64(o.PacketID)),
			fmtFloat(o.RxLat, 7),
			fmtFloat(o.RxLon, 7),
			fmtFloatOrEmpty(o.RxAltM, 2),
			fmtFloatOrEmpty(o.RxSpeedMps, 2),
			fmtFloatOrEmpty(o.RxHeadingDeg, 1),
			fmtFloatOrEmpty(o.HDOP, 2),
			fmtIntOrEmpty(o.Sats),
			fmtFloat(o.RSSIdBm, 1),
			fmtFloatOrEmpty(o.SNRdB, 2),
			fmtUint(o.FreqHz),
			fmtUint(uint64(o.BWHz)),
			o.Preset,
			fmt.Sprintf("0x%02x", o.ChannelHash),
			o.ChannelName,
			fmtBool(o.Decrypted),
			o.PortName,
			fmtBoolPtr(o.PayloadCRCOk),
			fmtIntOrEmpty(o.HopLimit),
			fmtIntOrEmpty(o.HopStart),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// --- small formatting helpers -------------------------------------------------

func fmtUint(v uint64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatUint(v, 10)
}

func fmtIntOrEmpty(v int) string {
	if v == 0 {
		return ""
	}
	return strconv.Itoa(v)
}

func fmtFloat(v float64, prec int) string {
	return strconv.FormatFloat(v, 'f', prec, 64)
}

func fmtFloatOrEmpty(v float64, prec int) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', prec, 64)
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func fmtBoolPtr(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(csvTimeFormat)
}
