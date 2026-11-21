/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: live Google Earth KML feed.
 *
 * Keeps the last known position and a short track for every node heard
 * with a trusted POSITION or ATAK PLI, and renders them as KML on demand.
 * Same two-document layout as radiosonde_auto_rx:
 *
 *   GET /live.kml       -- a NetworkLink only. Google Earth loads this
 *                          once and then re-polls the feed URL every
 *                          --kml-refresh seconds (onInterval).
 *   GET /live_feed.kml  -- the data: one Folder per node holding its
 *                          latest Point, its track LineString, and a
 *                          line-of-sight line from this station (when
 *                          gpsd has a fix), plus the station itself.
 *
 * Node labels come from the caller (ATAK callsign) or node_db
 * (NODEINFO long_name), falling back to !nodeid. All remote-controlled
 * strings are escaped before they reach the KML.
 */

#ifndef KML_LIVE_H
#define KML_LIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define KML_LIVE_MAX_NODES  256   /* least-recently-heard node evicted past this */
#define KML_LIVE_TRACK_LEN  64    /* track points kept per node */
#define KML_LIVE_STALE_S    3600  /* nodes not heard for this long draw grey */

typedef struct kml_live_obs {
    uint32_t    id;
    double      lat, lon;
    bool        have_alt;
    double      alt_m;
    const char *label;      /* ATAK callsign etc.; NULL/"" -> node_db / !id */
    const char *channel;    /* matched channel name; may be NULL/"" */
    float       snr_db, rssi_db;
    uint64_t    freq_hz;    /* 0 = unknown */
    time_t      when;
} kml_live_obs_t;

typedef struct kml_live_station {
    const char *name;       /* NULL/"" -> "RX station" */
    double      lat, lon, alt_m;
} kml_live_station_t;

/* Record a position. Ignores (0,0) and out-of-range coordinates. */
void kml_live_note(const kml_live_obs_t *obs);

/* Forget everything (tests). */
void kml_live_reset(void);

/* Both return a malloc'd NUL-terminated document (caller frees) and set
 * *len if non-NULL; NULL on allocation failure. */
char *kml_live_network_link(const char *feed_url, int refresh_s, size_t *len);
char *kml_live_feed(const kml_live_station_t *station, time_t now, size_t *len);

#endif
