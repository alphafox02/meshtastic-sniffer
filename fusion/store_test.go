// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

func TestEventStore_AppendAndRecent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 10; i++ {
		if err := s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got, err := s.Recent(5)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5", len(got))
	}
	// Recent returns oldest-to-newest; we appended 0..9 so the last 5 are 5..9.
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i+5))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s", i, ev, want)
		}
	}
}

func TestEventStore_RingTrimsAtCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 5)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 20; i++ {
		if err := s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := s.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 5 {
		t.Fatalf("count=%d want 5 (ring should trim past cap)", n)
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5", len(got))
	}
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i+15))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s (oldest-to-newest ordering)", i, ev, want)
		}
	}
}

func TestEventStore_PersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s1, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	for i := 0; i < 7; i++ {
		_ = s1.Append([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	// Reopen and verify the events are still there.
	s2, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer s2.Close()
	got, err := s2.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("len(got)=%d want 7", len(got))
	}
	for i, ev := range got {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i))
		if !bytes.Equal(ev, want) {
			t.Fatalf("Recent[%d] = %s, want %s", i, ev, want)
		}
	}
}

func TestEventStore_NilSafe(t *testing.T) {
	var s *EventStore
	if err := s.Append([]byte(`{}`)); err != nil {
		t.Fatalf("nil append: %v", err)
	}
	got, err := s.Recent(10)
	if err != nil || got != nil {
		t.Fatalf("nil recent: got=%v err=%v", got, err)
	}
	n, err := s.Count()
	if err != nil || n != 0 {
		t.Fatalf("nil count: %d err=%v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
}

func TestEventStore_EmptyPathReturnsNil(t *testing.T) {
	s, err := OpenEventStore("", 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store for empty path, got %v", s)
	}
}

func TestSSEHub_PublishMirrorsToStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	hub := newSSEHub()
	hub.AttachStore(s)

	for i := 0; i < 5; i++ {
		hub.Publish([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	got, err := s.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got)=%d want 5 (Publish didn't mirror to store)", len(got))
	}
}

func TestSSEHub_HydratesFromStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := OpenEventStore(path, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 4; i++ {
		_ = s.Append([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	hub := newSSEHub()
	if err := hub.HydrateFromStore(s); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	hub.AttachStore(s)
	defer s.Close()

	// New SSE client should see all 4 events on connect via the
	// register replay path.
	_, replay, unregister := hub.register()
	defer unregister()
	if len(replay) != 4 {
		t.Fatalf("replay len=%d want 4 (hub didn't preload from store)", len(replay))
	}
	for i, ev := range replay {
		want := []byte(fmt.Sprintf(`{"i":%d}`, i))
		if !bytes.Equal(ev, want) {
			t.Fatalf("replay[%d] = %s, want %s", i, ev, want)
		}
	}
}
