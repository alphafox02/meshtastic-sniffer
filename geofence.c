/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: geofence alerts.
 *
 * INI-style polygon loader + point-in-polygon test (ray casting). On
 * every POSITION decode, fires GEOFENCE_ENTRY / GEOFENCE_EXIT events
 * when a node's inside-status for any polygon flips.
 *
 * Bounded-state design: per-(node, polygon) inside flags live in a
 * fixed-size hash table. Capacity covers a few thousand node/polygon
 * pairs, far more than a typical mesh deployment will produce.
 */

#include "geofence.h"

#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void web_publish_line(const char *json, size_t len);
extern void webhook_publish(const char *event_name, const char *json, size_t len,
                            const char *summary);

#define GEO_MAX_POLYGONS    32
#define GEO_MAX_VERTICES    256
#define GEO_STATE_BUCKETS   2048

typedef struct {
    char    name[32];
    int     n_vertices;
    double  lat[GEO_MAX_VERTICES];
    double  lon[GEO_MAX_VERTICES];
} polygon_t;

typedef struct state_entry {
    uint32_t node_id;
    int      polygon_idx; /* -1 = empty slot */
    bool     inside;
} state_entry_t;

static polygon_t      g_polys[GEO_MAX_POLYGONS];
static int            g_poly_count = 0;
static state_entry_t  g_state[GEO_STATE_BUCKETS];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int            g_started = 0;

/* Open-addressed hash table; key is (node_id << 8) | polygon_idx. */
static uint32_t state_hash(uint32_t node_id, int poly_idx)
{
    uint32_t h = node_id * 2654435761u;
    h ^= (uint32_t)poly_idx * 2246822519u;
    return h;
}

static state_entry_t *state_find_or_make(uint32_t node_id, int poly_idx)
{
    uint32_t h = state_hash(node_id, poly_idx) % GEO_STATE_BUCKETS;
    for (int probe = 0; probe < GEO_STATE_BUCKETS; ++probe) {
        state_entry_t *e = &g_state[(h + probe) % GEO_STATE_BUCKETS];
        if (e->polygon_idx == -1) {
            e->node_id = node_id;
            e->polygon_idx = poly_idx;
            e->inside = false;
            return e;
        }
        if (e->node_id == node_id && e->polygon_idx == poly_idx) return e;
    }
    return NULL; /* table full -- shouldn't happen at expected scales */
}

/* Ray-casting point-in-polygon. Treats consecutive vertices as edges
 * and the last vertex as connected back to the first. */
static bool point_in_polygon(const polygon_t *p, double lat, double lon)
{
    bool inside = false;
    int n = p->n_vertices;
    for (int i = 0, j = n - 1; i < n; j = i++) {
        double yi = p->lat[i], xi = p->lon[i];
        double yj = p->lat[j], xj = p->lon[j];
        if (((yi > lat) != (yj > lat)) &&
            (lon < (xj - xi) * (lat - yi) / (yj - yi + 1e-12) + xi)) {
            inside = !inside;
        }
    }
    return inside;
}

/* ---- File loader ---- */

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) ++s;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = 0;
    return s;
}

bool geofence_init(const char *path)
{
    if (g_started) return true;
    if (!path) return false;
    for (int i = 0; i < GEO_STATE_BUCKETS; ++i) g_state[i].polygon_idx = -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "geofence: cannot open %s\n", path);
        return false;
    }
    char line[256];
    polygon_t *cur = NULL;
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (!*p || *p == '#' || *p == ';') continue;
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) continue;
            *end = 0;
            if (g_poly_count >= GEO_MAX_POLYGONS) continue;
            cur = &g_polys[g_poly_count++];
            memset(cur, 0, sizeof(*cur));
            strncpy(cur->name, p + 1, sizeof(cur->name) - 1);
        } else if (cur) {
            double lat, lon;
            if (sscanf(p, "%lf , %lf", &lat, &lon) == 2 ||
                sscanf(p, "%lf,%lf", &lat, &lon) == 2) {
                if (cur->n_vertices < GEO_MAX_VERTICES) {
                    cur->lat[cur->n_vertices] = lat;
                    cur->lon[cur->n_vertices] = lon;
                    ++cur->n_vertices;
                }
            }
        }
    }
    fclose(f);
    int n_with_verts = 0;
    for (int i = 0; i < g_poly_count; ++i)
        if (g_polys[i].n_vertices >= 3) ++n_with_verts;
    fprintf(stderr, "geofence: loaded %d polygon(s) from %s (%d usable, >= 3 vertices)\n",
            g_poly_count, path, n_with_verts);
    if (n_with_verts == 0) return false;
    g_started = 1;
    return true;
}

void geofence_shutdown(void)
{
    g_started = 0;
}

void geofence_check(uint32_t node_id, double lat, double lon)
{
    if (!g_started) return;
    if (lat == 0.0 && lon == 0.0) return; /* unset / null position */

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_poly_count; ++i) {
        if (g_polys[i].n_vertices < 3) continue;
        bool now_in = point_in_polygon(&g_polys[i], lat, lon);
        state_entry_t *st = state_find_or_make(node_id, i);
        if (!st) continue;
        if (st->inside == now_in) continue;
        bool was_in = st->inside;
        st->inside = now_in;

        const char *event = now_in ? "GEOFENCE_ENTRY" : "GEOFENCE_EXIT";
        char line[256];
        int n = snprintf(line, sizeof(line),
            "{\"event\":\"%s\",\"from\":\"!%08x\",\"polygon\":\"%s\","
            "\"lat\":%.6f,\"lon\":%.6f}\n",
            event, node_id, g_polys[i].name, lat, lon);
        if (n > 0) {
            fwrite(line, 1, (size_t)n, stdout); fflush(stdout);
            web_publish_line(line, (size_t)n);
            char sum[160];
            snprintf(sum, sizeof(sum),
                     "!%08x %s polygon '%s' at %.5f,%.5f",
                     node_id, now_in ? "entered" : "exited",
                     g_polys[i].name, lat, lon);
            webhook_publish(event, line, (size_t)n, sum);
            if (was_in)
                fprintf(stderr, "[geofence] !%08x EXITED %s\n", node_id, g_polys[i].name);
            else
                fprintf(stderr, "[geofence] !%08x ENTERED %s\n", node_id, g_polys[i].name);
        }
    }
    pthread_mutex_unlock(&g_mu);
}
