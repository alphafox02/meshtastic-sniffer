// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// HTTP API endpoint tests via httptest. Exercises the same handlers
// the live server registers so a regression in routing or auth is
// caught here, not from a 401-storm in production.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newAPIHandler builds the same wrapped /api/* mux that startWebServer
// installs, plus an open / handler. Lets tests hit the real mux
// without spinning up a TCP listener.
func newAPIHandler(t *testing.T, registry *Registry, hub *SSEHub, apiToken string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/sensors", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(registry.List())
		case http.MethodPost:
			var s Sensor
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				jsonError(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if err := registry.Add(&s); err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			jsonOK(w, map[string]string{"added": s.Name})
		default:
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	apiMux.HandleFunc("/api/sensors/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path[len("/api/sensors/"):]
		if name == "" {
			jsonError(w, "missing name", http.StatusBadRequest)
			return
		}
		if err := registry.Remove(name); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"removed": name})
	})
	wrapped := authWrap(apiMux, apiToken)
	mux.Handle("/api/", wrapped)
	mux.Handle("/events", wrapped)
	return mux
}

func newTestRegistryUnauthed(t *testing.T) *Registry {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r, err := NewRegistry(ctx, dir+"/sensors.json", nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestAPI_GetSensorsEmpty(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("body=%q want []", body)
	}
}

func TestAPI_AddSensorAndList(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	post := httptest.NewRequest(http.MethodPost, "/api/sensors",
		strings.NewReader(`{"name":"alpha","zmq":"tcp://127.0.0.1:7008"}`))
	post.Header.Set("Content-Type", "application/json")
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, post)
	if pw.Code != http.StatusOK {
		t.Fatalf("POST status=%d body=%s", pw.Code, pw.Body.String())
	}
	get := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	gw := httptest.NewRecorder()
	h.ServeHTTP(gw, get)
	var list []Sensor
	if err := json.Unmarshal(gw.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list) != 1 || list[0].Name != "alpha" {
		t.Fatalf("list=%+v", list)
	}
}

func TestAPI_DeleteSensor(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	_ = r.Add(&Sensor{Name: "to-delete", Zmq: "tcp://x:1"})
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/to-delete", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if list := r.List(); len(list) != 0 {
		t.Fatalf("post-delete list=%+v want empty", list)
	}
}

func TestAPI_DeleteUnknownIs404(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/ghost", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", w.Code)
	}
}

func TestAPI_AuthBlocksApiButNotIndex(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "secret123")

	// / always open
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/ status=%d want 200 even with auth on", w.Code)
	}

	// /api/sensors blocked
	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/api/sensors status=%d want 401", w.Code)
	}

	// /api/sensors with bearer accepted
	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/api/sensors with bearer status=%d want 200", w.Code)
	}
}

func TestAPI_BadPostBodyIs400(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/sensors", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestAPI_AddSensorMissingFieldsIs400(t *testing.T) {
	r := newTestRegistryUnauthed(t)
	h := newAPIHandler(t, r, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/sensors",
		strings.NewReader(`{"name":"missing-zmq"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (sensor needs zmq endpoint)", w.Code)
	}
}
