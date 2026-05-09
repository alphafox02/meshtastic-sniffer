// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newTestRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sensors.json")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r, err := NewRegistry(ctx, path, nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r, path
}

func TestRegistry_AddListRemove(t *testing.T) {
	r, _ := newTestRegistry(t)
	if err := r.Add(&Sensor{Name: "alpha", Zmq: "tcp://127.0.0.1:7008"}); err != nil {
		t.Fatalf("Add alpha: %v", err)
	}
	if err := r.Add(&Sensor{Name: "bravo", Zmq: "tcp://127.0.0.1:7009"}); err != nil {
		t.Fatalf("Add bravo: %v", err)
	}
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("List len=%d want 2", len(list))
	}
	if list[0].Name != "alpha" || list[1].Name != "bravo" {
		t.Fatalf("List not sorted by name: %+v", list)
	}
	if err := r.Remove("alpha"); err != nil {
		t.Fatalf("Remove alpha: %v", err)
	}
	list = r.List()
	if len(list) != 1 || list[0].Name != "bravo" {
		t.Fatalf("post-remove list = %+v", list)
	}
}

func TestRegistry_RejectsEmptyNameOrZmq(t *testing.T) {
	r, _ := newTestRegistry(t)
	cases := []struct {
		name string
		s    *Sensor
	}{
		{"nil", nil},
		{"empty name", &Sensor{Zmq: "tcp://x:1"}},
		{"empty zmq", &Sensor{Name: "x"}},
	}
	for _, tc := range cases {
		if err := r.Add(tc.s); err == nil {
			t.Errorf("%s: Add returned nil err", tc.name)
		}
	}
}

func TestRegistry_RemoveUnknown(t *testing.T) {
	r, _ := newTestRegistry(t)
	if err := r.Remove("ghost"); err == nil {
		t.Fatalf("expected error removing nonexistent sensor")
	}
}

func TestRegistry_PersistsAcrossReload(t *testing.T) {
	r1, path := newTestRegistry(t)
	if err := r1.Add(&Sensor{
		Name: "rooftop", Zmq: "tcp://10.0.0.5:7008",
		Api: "http://10.0.0.5:8888", ApiToken: "secret",
		Lat: 38.0, Lon: -77.0,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Read the persisted file directly to verify shape.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entries []Sensor
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "rooftop" || entries[0].ApiToken != "secret" {
		t.Fatalf("persisted entries = %+v", entries)
	}
	// File mode 0600: registry persists ApiToken which is credential-class.
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := stat.Mode().Perm(); mode != 0600 {
		t.Fatalf("file mode = %#o want 0600", mode)
	}
	// Reload from a fresh registry pointed at the same path.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r2, err := NewRegistry(ctx, path, nil)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	list := r2.List()
	if len(list) != 1 || list[0].Lat != 38.0 || list[0].ApiToken != "secret" {
		t.Fatalf("reloaded list = %+v", list)
	}
}

func TestRegistry_AddOverwritesByName(t *testing.T) {
	r, _ := newTestRegistry(t)
	_ = r.Add(&Sensor{Name: "x", Zmq: "tcp://a:1", ApiToken: "old"})
	_ = r.Add(&Sensor{Name: "x", Zmq: "tcp://a:1", ApiToken: "new"})
	list := r.List()
	if len(list) != 1 || list[0].ApiToken != "new" {
		t.Fatalf("Add did not overwrite: %+v", list)
	}
}
