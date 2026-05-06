// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/c2.go: command fan-out from the fusion dashboard to every
// registered sensor's HTTP /api/* endpoint.
//
// When the operator clicks "Add key" in the fusion UI, the new key
// should land on every sensor in one shot. The wire-level transport
// is just HTTP POST to each sensor's existing /api/<endpoint>, with
// the optional bearer token from the registry entry. Per-sensor
// success/failure is collected and returned as JSON so the dashboard
// can show partial-failure states.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// FanoutResult is one sensor's reply to a fan-out command.
type FanoutResult struct {
	Sensor string `json:"sensor"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
}

// fanoutClient is shared across all fan-out calls. 5s per-request
// timeout: command APIs return fast, anything longer is a sign the
// sensor is hung and we should move on.
var fanoutClient = &http.Client{Timeout: 5 * time.Second}

// fanoutCommand pushes `body` to every registered sensor in parallel.
// Per-sensor transport pick:
//   - if a DEALER session is open for this sensor name, use DEALER
//     (works through NAT; no inbound port required on the sensor)
//   - else if the sensor has an Api endpoint, fall back to HTTP POST
//   - else mark as "no transport"
// Results come back in registry order. Adds the sensor's ApiToken as
// a Bearer header on HTTP fallback when set.
func fanoutCommand(registry *Registry, path string, body []byte) []FanoutResult {
	sensors := registry.List()
	dealer := registry.DealerHub()
	results := make([]FanoutResult, len(sensors))

	// Translate fan-out path -> dealer command name. The DEALER side
	// uses underscored command names; HTTP side uses dashed paths.
	cmdName := map[string]string{
		"keys":          "keys_add",
		"share-url":     "share_url",
		"extra-freq":    "extra_freq",
		"cot-multicast": "cot_multicast",
	}[path]

	var wg sync.WaitGroup
	for i := range sensors {
		s := sensors[i]
		idx := i
		// Prefer DEALER if available.
		if dealer != nil && cmdName != "" && dealer.HasSession(s.Name) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				status, replyBody, err := dealer.SendCommand(s.Name, cmdName, string(body), 5*time.Second)
				if err != nil {
					results[idx] = FanoutResult{Sensor: s.Name, Error: "dealer: " + err.Error()}
					return
				}
				results[idx] = FanoutResult{
					Sensor: s.Name, Status: status, Body: replyBody,
				}
			}()
			continue
		}
		if s.Api == "" {
			results[idx] = FanoutResult{Sensor: s.Name, Error: "no api endpoint configured"}
			continue
		}
		wg.Add(1)
		go func(s Sensor) {
			defer wg.Done()
			url := s.Api + "/api/" + path
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				results[idx] = FanoutResult{Sensor: s.Name, Error: err.Error()}
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if s.ApiToken != "" {
				req.Header.Set("Authorization", "Bearer "+s.ApiToken)
			}
			resp, err := fanoutClient.Do(req)
			if err != nil {
				results[idx] = FanoutResult{Sensor: s.Name, Error: err.Error()}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			results[idx] = FanoutResult{
				Sensor: s.Name, Status: resp.StatusCode, Body: string(b),
			}
		}(s)
	}
	wg.Wait()
	return results
}

// installFanoutHandlers registers /api/fanout/<endpoint> handlers on
// the given mux. Each one reads the request body, calls fanoutCommand
// against the registry's current sensor list, and replies with a
// per-sensor JSON array.
func installFanoutHandlers(mux *http.ServeMux, registry *Registry) {
	endpoints := []string{"keys", "share-url", "extra-freq", "cot-multicast"}
	for _, ep := range endpoints {
		ep := ep // capture
		mux.HandleFunc("/api/fanout/"+ep, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"read body: %s"}`, err),
					http.StatusBadRequest)
				return
			}
			results := fanoutCommand(registry, ep, body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"endpoint": ep,
				"results":  results,
			})
		})
	}
}
