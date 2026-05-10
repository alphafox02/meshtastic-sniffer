// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/jsonout.go: structured JSON sidecar.
//
// Companion file to the KML/CSV exports. Every NodeAggregate +
// Session is emitted in machine-readable form so downstream tooling
// (re-estimators, visualizers, the future WiGLE submitter, etc.)
// doesn't have to parse the description CDATA out of the KML or
// re-fetch the SQLite DB.

package main

import (
	"encoding/json"
	"io"
)

// JSONExport is the top-level shape of the sidecar file.
type JSONExport struct {
	Format  string          `json:"format"`           // FormatVersion
	Session Session         `json:"session"`
	Nodes   []*NodeAggregate `json:"nodes"`
	Track   []TrackPoint     `json:"track,omitempty"`
}

// WriteJSON emits a JSONExport to `w`. Indented with two spaces so a
// human reading it in a text editor doesn't see a one-line wall.
func WriteJSON(w io.Writer, sess Session, aggs []*NodeAggregate, track []TrackPoint) error {
	out := JSONExport{
		Format:  FormatVersion,
		Session: sess,
		Nodes:   aggs,
		Track:   track,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&out)
}
