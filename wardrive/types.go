// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/types.go: shared data shapes for the wardrive binary.
//
// Three layers:
//
//	Observation       -- one row per heard frame (raw, fully-fidelity)
//	NodeAggregate     -- one row per node (the export format users will look at)
//	Track             -- the operator's GPS path during the session
//
// All public fields are emitted by at least one of the format writers
// (CSV, KML, JSON), so changing them changes the wire format. Treat
// the field set as semi-stable: deletions are a major-version bump,
// additions are a minor-version bump.

package main

import "time"

// Observation is one Meshtastic frame received during the wardrive,
// tagged with the operator's GPS fix at the moment of receipt.
type Observation struct {
	TS              time.Time `json:"ts_utc"`
	NodeID          string    `json:"node_id"`           // canonical "!433c0b98"
	PacketID        uint32    `json:"packet_id,omitempty"`
	RxLat           float64   `json:"rx_lat"`            // operator GPS lat at receive
	RxLon           float64   `json:"rx_lon"`            // operator GPS lon at receive
	RxAltM          float64   `json:"rx_alt_m,omitempty"`
	RxSpeedMps      float64   `json:"rx_speed_mps,omitempty"`
	RxHeadingDeg    float64   `json:"rx_heading_deg,omitempty"`
	HDOP            float64   `json:"hdop,omitempty"`     // when gpsd reports it
	Sats            int       `json:"sats,omitempty"`
	RSSIdBm         float64   `json:"rssi_dbm"`
	SNRdB           float64   `json:"snr_db,omitempty"`
	FreqHz          uint64    `json:"freq_hz"`            // slot center
	BWHz            uint32    `json:"bw_hz"`              // 125000 / 250000 / 500000
	Preset          string    `json:"preset,omitempty"`   // "LongFast" etc.
	ChannelHash     uint8     `json:"channel_hash"`       // 1-byte routing hash
	ChannelName     string    `json:"channel_name,omitempty"` // only when decrypted
	Decrypted       bool      `json:"decrypted"`
	PortName        string    `json:"port_name,omitempty"`
	PayloadCRCOk    *bool     `json:"payload_crc_ok,omitempty"` // nil = no CRC, false = failed
	HopLimit        int       `json:"hop_limit,omitempty"`
	HopStart        int       `json:"hop_start,omitempty"`
	// SelfReportedLat/Lon when this frame was a POSITION_APP packet
	// that decrypted; otherwise zero. Aggregator uses these to
	// short-circuit centroid estimation when the node broadcasts.
	SelfReportedLat  float64 `json:"selfrep_lat,omitempty"`
	SelfReportedLon  float64 `json:"selfrep_lon,omitempty"`
	SelfReportedAltM float64 `json:"selfrep_alt_m,omitempty"`
	// LongName/ShortName when this frame was a NODEINFO_APP packet
	// that decrypted. Aggregator latches these onto the node summary.
	LongName  string `json:"long_name,omitempty"`
	ShortName string `json:"short_name,omitempty"`
	HWModel   uint32 `json:"hw_model,omitempty"`
	Role      uint32 `json:"role,omitempty"`
}

// NodeAggregate is the per-node summary. One row per node in the
// aggregated CSV / KML / JSON export. Built by Aggregate() over a
// slice of Observations.
type NodeAggregate struct {
	NodeID      string    `json:"node_id"`
	LongName    string    `json:"long_name,omitempty"`
	ShortName   string    `json:"short_name,omitempty"`
	HWModel     uint32    `json:"hw_model,omitempty"`
	Role        uint32    `json:"role,omitempty"`
	ChannelName string    `json:"channel_name,omitempty"`
	ChannelHash uint8     `json:"channel_hash"`
	Preset      string    `json:"preset,omitempty"`
	BWHz        uint32    `json:"bw_hz,omitempty"`
	FreqHz      uint64    `json:"freq_hz,omitempty"`
	FirstSeen   time.Time `json:"first_seen_utc"`
	LastSeen    time.Time `json:"last_seen_utc"`
	ObsCount    int       `json:"obs_count"`
	BestRSSIdBm float64   `json:"best_rssi_dbm"`
	BestRSSITS  time.Time `json:"best_rssi_ts_utc"`
	BestSNRdB   float64   `json:"best_snr_db,omitempty"`
	// Estimate: where do we think this node is?
	EstLat          float64 `json:"est_lat"`
	EstLon          float64 `json:"est_lon"`
	EstUncertaintyM float64 `json:"est_uncertainty_m"` // 1-sigma in meters
	EstMethod       string  `json:"est_method"`        // "self-reported" | "rssi2-weighted-centroid" | "path-loss-inversion"
	// Self-reported position from any decrypted POSITION packet
	// during the session. Empty when never seen. Note: when
	// EstMethod = "self-reported" this is the source of EstLat/Lon.
	SelfReportedLat  float64    `json:"selfrep_lat,omitempty"`
	SelfReportedLon  float64    `json:"selfrep_lon,omitempty"`
	SelfReportedAltM float64    `json:"selfrep_alt_m,omitempty"`
	SelfReportedTS   *time.Time `json:"selfrep_ts_utc,omitempty"`
	// Bookkeeping for cross-session aggregation.
	SessionID string `json:"session_id,omitempty"`
	StationID string `json:"station_id,omitempty"`
}

// TrackPoint is one decimated GPS fix during the wardrive, used to
// render the operator's path polyline in the KML.
type TrackPoint struct {
	TS         time.Time `json:"ts_utc"`
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	AltM       float64   `json:"alt_m,omitempty"`
	SpeedMps   float64   `json:"speed_mps,omitempty"`
	HeadingDeg float64   `json:"heading_deg,omitempty"`
	HDOP       float64   `json:"hdop,omitempty"`
	Sats       int       `json:"sats,omitempty"`
}

// Session is the run-level metadata that lands in every export
// header line so a viewer can tell what kit/region/dates produced
// the file. Carried in the CSV preamble and the KML <Document><name>.
type Session struct {
	SessionID  string    `json:"session_id"`
	StationID  string    `json:"station_id,omitempty"`
	SDR        string    `json:"sdr,omitempty"`        // "hackrf", "rtlsdr", ...
	Region     string    `json:"region,omitempty"`     // "US", "EU_868", ...
	Presets    string    `json:"presets,omitempty"`    // "LongFast,MediumFast"
	StartTS    time.Time `json:"start_ts_utc"`
	EndTS      time.Time `json:"end_ts_utc,omitempty"`
	AppRelease string    `json:"app_release"`          // e.g. "meshtastic-wardrive-1.0"
}

// FormatVersion is the version tag embedded in the CSV preamble line.
// Bump on incompatible column changes; minor field additions can keep
// the same major and announce themselves via the appRelease tag.
const FormatVersion = "MeshtasticWardrive-1.0"

// AppName is the binary's self-identification string. Embedded in
// Session.AppRelease and the CSV preamble so downstream tools
// (including any future WiGLE submitter) can attribute observations
// to the producing version.
const AppName = "meshtastic-wardrive"

// AppVersion is the binary's version string. Bump on any user-visible
// behavior change. Build-time -ldflags can override at link time.
var AppVersion = "1.0.0-dev"
