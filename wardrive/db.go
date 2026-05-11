// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/db.go: SQLite storage backing the wardrive session.
//
// Layout follows the Kismet convention: per-frame observations and
// per-fix GPS tracks live in append-only tables; the per-node
// aggregate table is rebuilt on demand at export time so we never
// have to keep it consistent during the drive.
//
// Pure-Go (modernc.org/sqlite) -- no cgo, single static binary.

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB plus prepared insert statements for the hot
// observation/track write paths. The wardrive runs at most a few
// hundred inserts per second; the prepared statements amortize the
// per-insert parse cost.
type DB struct {
	db   *sql.DB
	path string

	stmtInsertObs   *sql.Stmt
	stmtInsertTrack *sql.Stmt
}

// schema is run on every Open(); CREATE IF NOT EXISTS so repeated
// opens of the same file are idempotent. Mirrors the design notes:
// observations are append-only, nodes are derived.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS sessions (
  session_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  start_ts     REAL    NOT NULL,
  end_ts       REAL,
  station_id   TEXT,
  region       TEXT,
  presets_csv  TEXT,
  sniffer_ver  TEXT,
  notes        TEXT
);

CREATE TABLE IF NOT EXISTS tracks (
  session_id  INTEGER NOT NULL REFERENCES sessions(session_id),
  ts          REAL    NOT NULL,
  lat         REAL    NOT NULL,
  lon         REAL    NOT NULL,
  alt_m       REAL,
  speed_mps   REAL,
  heading_deg REAL,
  hdop        REAL,
  sats        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tracks_session_ts ON tracks(session_id, ts);

CREATE TABLE IF NOT EXISTS observations (
  obs_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    INTEGER NOT NULL REFERENCES sessions(session_id),
  ts            REAL    NOT NULL,
  node_id       TEXT    NOT NULL,
  packet_id     INTEGER,
  rx_lat        REAL,
  rx_lon        REAL,
  rx_alt_m      REAL,
  rx_speed_mps  REAL,
  rx_heading    REAL,
  hdop          REAL,
  sats          INTEGER,
  rssi_dbm      REAL,
  snr_db        REAL,
  freq_hz       INTEGER,
  bw_hz         INTEGER,
  preset        TEXT,
  channel_hash  INTEGER,
  channel_name  TEXT,
  decrypted     INTEGER NOT NULL,
  port_name     TEXT,
  payload_crc_ok INTEGER,
  hop_limit     INTEGER,
  hop_start     INTEGER,
  selfrep_lat   REAL,
  selfrep_lon   REAL,
  selfrep_alt_m REAL,
  long_name     TEXT,
  short_name    TEXT,
  hw_model      INTEGER,
  role          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs_node_ts ON observations(node_id, ts);
CREATE INDEX IF NOT EXISTS idx_obs_session ON observations(session_id);
`

// OpenDB opens (or creates) a wardrive SQLite file at `path` and
// runs the schema. Returns a *DB with hot-path inserts prepared.
func OpenDB(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// Best-effort mkdir; sqlite open will surface the real error if
		// the path is still bad.
		_ = ensureDirAll(dir)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := conn.Exec(schema); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("schema %s: %w", path, err)
	}
	d := &DB{db: conn, path: path}
	if err := d.prepare(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) prepare() error {
	var err error
	d.stmtInsertObs, err = d.db.Prepare(`
		INSERT INTO observations (
		  session_id, ts, node_id, packet_id,
		  rx_lat, rx_lon, rx_alt_m, rx_speed_mps, rx_heading,
		  hdop, sats,
		  rssi_dbm, snr_db, freq_hz, bw_hz, preset,
		  channel_hash, channel_name, decrypted, port_name, payload_crc_ok,
		  hop_limit, hop_start,
		  selfrep_lat, selfrep_lon, selfrep_alt_m,
		  long_name, short_name, hw_model, role
		) VALUES (
		  ?, ?, ?, ?,
		  ?, ?, ?, ?, ?,
		  ?, ?,
		  ?, ?, ?, ?, ?,
		  ?, ?, ?, ?, ?,
		  ?, ?,
		  ?, ?, ?,
		  ?, ?, ?, ?
		)`)
	if err != nil {
		return fmt.Errorf("prepare insert observation: %w", err)
	}
	d.stmtInsertTrack, err = d.db.Prepare(`
		INSERT INTO tracks (session_id, ts, lat, lon, alt_m, speed_mps, heading_deg, hdop, sats)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert track: %w", err)
	}
	return nil
}

// Close releases the underlying *sql.DB. Safe on nil.
func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	if d.stmtInsertObs != nil {
		_ = d.stmtInsertObs.Close()
	}
	if d.stmtInsertTrack != nil {
		_ = d.stmtInsertTrack.Close()
	}
	return d.db.Close()
}

// StartSession inserts a new sessions row and returns its id, plus
// the start timestamp the row carries.
func (d *DB) StartSession(stationID, region, presets, snifferVer, notes string) (int64, time.Time, error) {
	now := time.Now().UTC()
	res, err := d.db.Exec(`INSERT INTO sessions (start_ts, station_id, region, presets_csv, sniffer_ver, notes)
	                        VALUES (?, ?, ?, ?, ?, ?)`,
		float64(now.UnixNano())/1e9, stationID, region, presets, snifferVer, notes)
	if err != nil {
		return 0, time.Time{}, err
	}
	id, err := res.LastInsertId()
	return id, now, err
}

// EndSession stamps end_ts on the session row.
func (d *DB) EndSession(sessionID int64) error {
	_, err := d.db.Exec(`UPDATE sessions SET end_ts = ? WHERE session_id = ?`,
		float64(time.Now().UTC().UnixNano())/1e9, sessionID)
	return err
}

// InsertObservation persists one observation. Uses the prepared
// statement so the hot path doesn't pay parse cost per row.
func (d *DB) InsertObservation(sessionID int64, o *Observation) error {
	var crc any
	if o.PayloadCRCOk != nil {
		v := 0
		if *o.PayloadCRCOk {
			v = 1
		}
		crc = v
	}
	dec := 0
	if o.Decrypted {
		dec = 1
	}
	_, err := d.stmtInsertObs.Exec(
		sessionID, floatTS(o.TS), o.NodeID, o.PacketID,
		nullableFloat(o.RxLat), nullableFloat(o.RxLon), nullableFloat(o.RxAltM),
		nullableFloat(o.RxSpeedMps), nullableFloat(o.RxHeadingDeg),
		nullableFloat(o.HDOP), nullableInt(o.Sats),
		nullableFloat(o.RSSIdBm), nullableFloat(o.SNRdB),
		nullableUint(o.FreqHz), nullableUint(uint64(o.BWHz)), o.Preset,
		int(o.ChannelHash), o.ChannelName, dec, o.PortName, crc,
		nullableInt(o.HopLimit), nullableInt(o.HopStart),
		nullableFloat(o.SelfReportedLat), nullableFloat(o.SelfReportedLon), nullableFloat(o.SelfReportedAltM),
		o.LongName, o.ShortName, nullableUint(uint64(o.HWModel)), nullableUint(uint64(o.Role)),
	)
	return err
}

// InsertTrack persists one GPS fix into the tracks table.
func (d *DB) InsertTrack(sessionID int64, t *TrackPoint) error {
	_, err := d.stmtInsertTrack.Exec(
		sessionID, floatTS(t.TS), t.Lat, t.Lon,
		nullableFloat(t.AltM), nullableFloat(t.SpeedMps), nullableFloat(t.HeadingDeg),
		nullableFloat(t.HDOP), nullableInt(t.Sats),
	)
	return err
}

// LoadObservations returns every observation in a session ordered by
// ts. When `sessionID` is 0, returns observations across all sessions.
func (d *DB) LoadObservations(sessionID int64) ([]Observation, error) {
	var rows *sql.Rows
	var err error
	q := `SELECT ts, node_id, packet_id,
	             rx_lat, rx_lon, rx_alt_m, rx_speed_mps, rx_heading,
	             hdop, sats,
	             rssi_dbm, snr_db, freq_hz, bw_hz, preset,
	             channel_hash, channel_name, decrypted, port_name, payload_crc_ok,
	             hop_limit, hop_start,
	             selfrep_lat, selfrep_lon, selfrep_alt_m,
	             long_name, short_name, hw_model, role
	      FROM observations`
	if sessionID > 0 {
		q += ` WHERE session_id = ? ORDER BY ts ASC`
		rows, err = d.db.Query(q, sessionID)
	} else {
		q += ` ORDER BY ts ASC`
		rows, err = d.db.Query(q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Observation
	for rows.Next() {
		var o Observation
		var ts float64
		var packetID sql.NullInt64
		var rxLat, rxLon, rxAlt, rxSpeed, rxHeading sql.NullFloat64
		var hdop sql.NullFloat64
		var sats sql.NullInt64
		var rssi, snr sql.NullFloat64
		var freq, bw sql.NullInt64
		var preset sql.NullString
		var chHash sql.NullInt64
		var chName sql.NullString
		var decrypted int
		var portName sql.NullString
		var crc sql.NullInt64
		var hopLim, hopStart sql.NullInt64
		var srLat, srLon, srAlt sql.NullFloat64
		var longName, shortName sql.NullString
		var hwModel, role sql.NullInt64

		if err := rows.Scan(&ts, &o.NodeID, &packetID,
			&rxLat, &rxLon, &rxAlt, &rxSpeed, &rxHeading,
			&hdop, &sats,
			&rssi, &snr, &freq, &bw, &preset,
			&chHash, &chName, &decrypted, &portName, &crc,
			&hopLim, &hopStart,
			&srLat, &srLon, &srAlt,
			&longName, &shortName, &hwModel, &role); err != nil {
			return nil, err
		}
		o.TS = floatToTime(ts)
		o.PacketID = uint32(packetID.Int64)
		o.RxLat = rxLat.Float64
		o.RxLon = rxLon.Float64
		o.RxAltM = rxAlt.Float64
		o.RxSpeedMps = rxSpeed.Float64
		o.RxHeadingDeg = rxHeading.Float64
		o.HDOP = hdop.Float64
		o.Sats = int(sats.Int64)
		o.RSSIdBm = rssi.Float64
		o.SNRdB = snr.Float64
		o.FreqHz = uint64(freq.Int64)
		o.BWHz = uint32(bw.Int64)
		o.Preset = preset.String
		o.ChannelHash = uint8(chHash.Int64)
		o.ChannelName = chName.String
		o.Decrypted = decrypted != 0
		o.PortName = portName.String
		if crc.Valid {
			b := crc.Int64 != 0
			o.PayloadCRCOk = &b
		}
		o.HopLimit = int(hopLim.Int64)
		o.HopStart = int(hopStart.Int64)
		o.SelfReportedLat = srLat.Float64
		o.SelfReportedLon = srLon.Float64
		o.SelfReportedAltM = srAlt.Float64
		o.LongName = longName.String
		o.ShortName = shortName.String
		o.HWModel = uint32(hwModel.Int64)
		o.Role = uint32(role.Int64)
		out = append(out, o)
	}
	return out, rows.Err()
}

// LoadTracks returns every track point in a session ordered by ts.
func (d *DB) LoadTracks(sessionID int64) ([]TrackPoint, error) {
	q := `SELECT ts, lat, lon, alt_m, speed_mps, heading_deg, hdop, sats
	      FROM tracks WHERE session_id = ? ORDER BY ts ASC`
	rows, err := d.db.Query(q, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrackPoint
	for rows.Next() {
		var t TrackPoint
		var ts float64
		var alt, speed, heading, hdop sql.NullFloat64
		var sats sql.NullInt64
		if err := rows.Scan(&ts, &t.Lat, &t.Lon, &alt, &speed, &heading, &hdop, &sats); err != nil {
			return nil, err
		}
		t.TS = floatToTime(ts)
		t.AltM = alt.Float64
		t.SpeedMps = speed.Float64
		t.HeadingDeg = heading.Float64
		t.HDOP = hdop.Float64
		t.Sats = int(sats.Int64)
		out = append(out, t)
	}
	return out, rows.Err()
}

// LoadSession reads a single session row and returns it as a
// Session struct (without the AppRelease field which lives in
// memory only).
func (d *DB) LoadSession(sessionID int64) (Session, error) {
	var s Session
	var startTS float64
	var endTS sql.NullFloat64
	var stationID, region, presets sql.NullString
	err := d.db.QueryRow(`SELECT session_id, start_ts, end_ts, station_id, region, presets_csv
	                       FROM sessions WHERE session_id = ?`, sessionID).Scan(
		&s.SessionID, &startTS, &endTS, &stationID, &region, &presets,
	)
	if err != nil {
		return s, err
	}
	s.StartTS = floatToTime(startTS)
	if endTS.Valid {
		s.EndTS = floatToTime(endTS.Float64)
	}
	s.StationID = stationID.String
	s.Region = region.String
	s.Presets = presets.String
	return s, nil
}

// ListSessions returns all sessions ordered most-recent first.
func (d *DB) ListSessions() ([]Session, error) {
	rows, err := d.db.Query(`SELECT session_id, start_ts, end_ts, station_id, region, presets_csv
	                          FROM sessions ORDER BY start_ts DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		var startTS float64
		var endTS sql.NullFloat64
		var stationID, region, presets sql.NullString
		if err := rows.Scan(&s.SessionID, &startTS, &endTS, &stationID, &region, &presets); err != nil {
			return nil, err
		}
		s.StartTS = floatToTime(startTS)
		if endTS.Valid {
			s.EndTS = floatToTime(endTS.Float64)
		}
		s.StationID = stationID.String
		s.Region = region.String
		s.Presets = presets.String
		out = append(out, s)
	}
	return out, rows.Err()
}

// CountObservations returns the row count of the observations table,
// restricted to one session if sessionID > 0. Used by the web status
// page and the export summary.
func (d *DB) CountObservations(sessionID int64) (int, error) {
	var n int
	if sessionID > 0 {
		return n, d.db.QueryRow(`SELECT COUNT(*) FROM observations WHERE session_id = ?`,
			sessionID).Scan(&n)
	}
	return n, d.db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&n)
}

// --- Session.SessionID is a string (e.g. "selftest-1") in the export
// format but an int64 PK in the database. The DB methods accept and
// return int64; the export code converts via fmt.Sprintf("%d", id) so
// the export-time SessionID field is a stringified int. ---

// floatTS converts a time.Time to seconds-since-epoch (with fractional
// nanoseconds preserved as fractional seconds). SQLite REAL stores
// ~15 significant digits which gives us microsecond resolution for
// modern timestamps -- plenty for the 1Hz/0.5Hz cadence we emit.
func floatTS(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

// floatToTime is the inverse of floatTS.
func floatToTime(f float64) time.Time {
	if f == 0 {
		return time.Time{}
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

// nullableFloat returns nil when v is zero (matches column NULL
// semantics so optional fields don't pollute downstream reads), else v.
func nullableFloat(v float64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableUint(v uint64) any {
	if v == 0 {
		return nil
	}
	return int64(v)
}

func ensureDirAll(dir string) error {
	return os.MkdirAll(dir, 0755)
}
