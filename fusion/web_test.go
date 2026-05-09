// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthWrap_NoTokenIsPassthrough(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "")
	r := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called {
		t.Fatalf("inner handler not called when token empty")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
}

func TestAuthWrap_RejectsMissingToken(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "secret")
	r := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called {
		t.Fatalf("inner handler called despite missing token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", w.Code)
	}
}

func TestAuthWrap_RejectsWrongToken(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "secret")
	r := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called {
		t.Fatalf("inner handler called for wrong token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", w.Code)
	}
}

func TestAuthWrap_AcceptsBearerHeader(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "secret")
	r := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called {
		t.Fatalf("inner handler not called for valid bearer")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
}

func TestAuthWrap_AcceptsQueryParam(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "secret")
	r := httptest.NewRequest(http.MethodGet, "/events?token=secret", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called {
		t.Fatalf("inner handler not called for valid query token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
}

func TestAuthWrap_HeaderTakesPrecedenceOverQuery(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authWrap(inner, "secret")
	r := httptest.NewRequest(http.MethodGet, "/api/sensors?token=wrong", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called {
		t.Fatalf("inner handler not called when header is valid even if query param is wrong")
	}
}

func TestAuthWrap_RejectsMalformedAuthHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := authWrap(inner, "secret")
	for _, hv := range []string{"secret", "Basic secret", "bearer secret", "Bearer", "Bearer "} {
		r := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
		r.Header.Set("Authorization", hv)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("malformed header %q returned status=%d, want 401", hv, w.Code)
		}
	}
}
