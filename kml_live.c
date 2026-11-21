/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: live Google Earth KML feed. See kml_live.h.
 */

#include "kml_live.h"
#include "node_db.h"

#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct track_pt {
    double lat, lon, alt_m;
} track_pt_t;

typedef struct live_node {
    uint32_t   id;
    char       label[64];
    char       channel[32];
    bool       have_alt;
    float      snr_db, rssi_db;
    uint64_t   freq_hz;
    time_t     first_seen, last_seen;
    uint32_t   reports;
    track_pt_t track[KML_LIVE_TRACK_LEN];   /* ring; newest at (head-1) */
    int        head, count;
} live_node_t;

static live_node_t     g_nodes[KML_LIVE_MAX_NODES];
static int             g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void copy_str(char *dst, size_t cap, const char *src)
{
    if (!src) src = "";
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

void kml_live_note(const kml_live_obs_t *o)
{
    if (!o) return;
    if (!isfinite(o->lat) || !isfinite(o->lon)) return;
    if (o->lat < -90.0 || o->lat > 90.0 || o->lon < -180.0 || o->lon > 180.0) return;
    /* (0,0) is what nodes without a GPS fix report; never a real sighting. */
    if (o->lat == 0.0 && o->lon == 0.0) return;

    pthread_mutex_lock(&g_lock);
    live_node_t *n = NULL;
    for (int i = 0; i < g_count; ++i)
        if (g_nodes[i].id == o->id) { n = &g_nodes[i]; break; }
    if (!n) {
        if (g_count < KML_LIVE_MAX_NODES) {
            n = &g_nodes[g_count++];
        } else {
            /* Evict the least-recently-heard node. */
            n = &g_nodes[0];
            for (int i = 1; i < g_count; ++i)
                if (g_nodes[i].last_seen < n->last_seen) n = &g_nodes[i];
        }
        memset(n, 0, sizeof(*n));
        n->id = o->id;
        n->first_seen = o->when;
    }
    if (o->label && *o->label)     copy_str(n->label, sizeof(n->label), o->label);
    if (o->channel && *o->channel) copy_str(n->channel, sizeof(n->channel), o->channel);
    n->have_alt  = o->have_alt;
    n->snr_db    = o->snr_db;
    n->rssi_db   = o->rssi_db;
    if (o->freq_hz) n->freq_hz = o->freq_hz;
    n->last_seen = o->when;
    n->reports++;

    /* Append to the track unless the node hasn't moved: a parked node
     * beaconing every 15 min would otherwise fill the ring with copies. */
    double alt = o->have_alt ? o->alt_m : 0.0;
    if (n->count > 0) {
        const track_pt_t *last = &n->track[(n->head + KML_LIVE_TRACK_LEN - 1) % KML_LIVE_TRACK_LEN];
        if (last->lat == o->lat && last->lon == o->lon && last->alt_m == alt) {
            pthread_mutex_unlock(&g_lock);
            return;
        }
    }
    n->track[n->head] = (track_pt_t){ o->lat, o->lon, alt };
    n->head = (n->head + 1) % KML_LIVE_TRACK_LEN;
    if (n->count < KML_LIVE_TRACK_LEN) n->count++;
    pthread_mutex_unlock(&g_lock);
}

void kml_live_reset(void)
{
    pthread_mutex_lock(&g_lock);
    g_count = 0;
    memset(g_nodes, 0, sizeof(g_nodes));
    pthread_mutex_unlock(&g_lock);
}

/* ---- growable output buffer ---- */

typedef struct sbuf {
    char  *p;
    size_t len, cap;
    bool   oom;
} sbuf_t;

static void sb_reserve(sbuf_t *b, size_t extra)
{
    if (b->oom || b->len + extra + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + extra + 1) cap *= 2;
    char *np = realloc(b->p, cap);
    if (!np) { b->oom = true; return; }
    b->p = np; b->cap = cap;
}

static void sb_printf(sbuf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { b->oom = true; return; }
    sb_reserve(b, (size_t)n);
    if (b->oom) return;
    va_start(ap, fmt);
    vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

/* Append s with XML special characters entity-escaped. Control bytes
 * (illegal in XML 1.0) become '?'. */
static void sb_xml(sbuf_t *b, const char *s)
{
    for (; s && *s; ++s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '&':  sb_printf(b, "&amp;");  break;
        case '<':  sb_printf(b, "&lt;");   break;
        case '>':  sb_printf(b, "&gt;");   break;
        case '"':  sb_printf(b, "&quot;"); break;
        case '\'': sb_printf(b, "&#39;");  break;
        default:
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') c = '?';
            sb_printf(b, "%c", c);
        }
    }
}

/* Append s for use inside an HTML <description>: HTML-escape it, then
 * XML-escape the result, so Google Earth's XML parser hands its HTML
 * renderer "&lt;" rather than a live '<' from a remote node name. */
static void sb_html(sbuf_t *b, const char *s)
{
    for (; s && *s; ++s) {
        switch (*s) {
        case '&':  sb_printf(b, "&amp;amp;");  break;
        case '<':  sb_printf(b, "&amp;lt;");   break;
        case '>':  sb_printf(b, "&amp;gt;");   break;
        case '"':  sb_printf(b, "&amp;quot;"); break;
        case '\'': sb_printf(b, "&amp;#39;");  break;
        default: { char one[2] = { *s, 0 }; sb_xml(b, one); }
        }
    }
}

/* An HTML line break, XML-escaped. */
#define BR "&lt;br&gt;"

static char *sb_finish(sbuf_t *b, size_t *len)
{
    if (b->oom) { free(b->p); return NULL; }
    sb_reserve(b, 0);
    if (b->oom) { free(b->p); return NULL; }
    b->p[b->len] = 0;
    if (len) *len = b->len;
    return b->p;
}

char *kml_live_network_link(const char *feed_url, int refresh_s, size_t *len)
{
    if (refresh_s < 1) refresh_s = 1;
    sbuf_t b = {0};
    sb_printf(&b,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
        "<Document>\n"
        "  <NetworkLink>\n"
        "    <name>Meshtastic live positions</name>\n"
        "    <open>1</open>\n"
        "    <Link>\n"
        "      <href>");
    sb_xml(&b, feed_url);
    sb_printf(&b,
        "</href>\n"
        "      <refreshMode>onInterval</refreshMode>\n"
        "      <refreshInterval>%d</refreshInterval>\n"
        "    </Link>\n"
        "  </NetworkLink>\n"
        "</Document>\n"
        "</kml>\n", refresh_s);
    return sb_finish(&b, len);
}

/* Styles use KML aabbggrr colours. Track amber matches auto_rx. */
static const char KML_STYLES[] =
    "  <Style id=\"node\">\n"
    "    <IconStyle><color>ff00ff00</color><scale>1.0</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon></IconStyle>\n"
    "    <LabelStyle><scale>0.85</scale></LabelStyle>\n"
    "  </Style>\n"
    "  <Style id=\"node-stale\">\n"
    "    <IconStyle><color>ff9e9e9e</color><scale>0.8</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon></IconStyle>\n"
    "    <LabelStyle><color>ffbdbdbd</color><scale>0.7</scale></LabelStyle>\n"
    "  </Style>\n"
    "  <Style id=\"track\">\n"
    "    <LineStyle><color>ff03bafc</color><width>2</width></LineStyle>\n"
    "  </Style>\n"
    "  <Style id=\"los\">\n"
    "    <LineStyle><color>80ffffff</color><width>1.5</width></LineStyle>\n"
    "  </Style>\n"
    "  <Style id=\"station\">\n"
    "    <IconStyle><color>fff8bd38</color><scale>1.2</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/target.png</href></Icon></IconStyle>\n"
    "  </Style>\n";

static void iso8601(char *out, size_t cap, time_t t)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void fmt_age(char *out, size_t cap, long s)
{
    if (s < 0) s = 0;
    if (s < 120)       snprintf(out, cap, "%lds ago", s);
    else if (s < 7200) snprintf(out, cap, "%ldm ago", s / 60);
    else               snprintf(out, cap, "%ldh %ldm ago", s / 3600, (s % 3600) / 60);
}

static void write_node(sbuf_t *b, const live_node_t *n, const kml_live_station_t *st, time_t now)
{
    char idstr[16];
    snprintf(idstr, sizeof(idstr), "!%08x", n->id);

    char name[NODE_DB_LONG_NAME + 4];
    if (n->label[0]) copy_str(name, sizeof(name), n->label);
    else {
        node_record_t rec;
        if (node_db_lookup(n->id, &rec) && rec.long_name[0]) copy_str(name, sizeof(name), rec.long_name);
        else copy_str(name, sizeof(name), idstr);
    }

    const track_pt_t *cur = &n->track[(n->head + KML_LIVE_TRACK_LEN - 1) % KML_LIVE_TRACK_LEN];
    long age = (long)(now - n->last_seen);
    bool stale = age > KML_LIVE_STALE_S;
    const char *altmode = n->have_alt ? "absolute" : "clampToGround";

    char when[32], ago[32];
    iso8601(when, sizeof(when), n->last_seen);
    fmt_age(ago, sizeof(ago), age);

    sb_printf(b, "  <Folder id=\"node_%08x\">\n    <name>", n->id);
    sb_xml(b, name);
    sb_printf(b, "</name>\n    <open>0</open>\n");

    /* Latest position. Google Earth renders <description> as HTML, so
     * lines are joined with <br> and remote strings go through sb_html.
     * No <TimeStamp>: it would switch on Google Earth's time slider,
     * which can hide placemarks outside the selected window. */
    sb_printf(b, "    <Placemark>\n      <name>");
    sb_xml(b, name);
    sb_printf(b, "</name>\n      <styleUrl>#%s</styleUrl>\n      <description>",
              stale ? "node-stale" : "node");
    sb_printf(b, "Node: %s" BR "Last heard: %s (%s)" BR "Position: %.6f, %.6f" BR,
              idstr, when, ago, cur->lat, cur->lon);
    if (n->have_alt) sb_printf(b, "Altitude: %.0f m" BR, cur->alt_m);
    if (n->channel[0]) { sb_printf(b, "Channel: "); sb_html(b, n->channel); sb_printf(b, BR); }
    if (n->freq_hz) sb_printf(b, "Frequency: %.3f MHz" BR, (double)n->freq_hz / 1e6);
    if (n->snr_db != 0.0f || n->rssi_db != 0.0f)
        sb_printf(b, "SNR: %.1f dB, RSSI: %.1f dB" BR, n->snr_db, n->rssi_db);
    sb_printf(b, "Position reports: %u, track points: %d",
              n->reports, n->count);
    sb_printf(b, "</description>\n"
                 "      <Point><altitudeMode>%s</altitudeMode><coordinates>%.6f,%.6f,%.1f</coordinates></Point>\n"
                 "    </Placemark>\n",
              altmode, cur->lon, cur->lat, cur->alt_m);

    /* Track, oldest to newest. */
    if (n->count >= 2) {
        sb_printf(b, "    <Placemark>\n      <name>Track</name>\n      <styleUrl>#track</styleUrl>\n"
                     "      <LineString><tessellate>1</tessellate><altitudeMode>%s</altitudeMode><coordinates>\n",
                  altmode);
        int start = (n->head + KML_LIVE_TRACK_LEN - n->count) % KML_LIVE_TRACK_LEN;
        for (int i = 0; i < n->count; ++i) {
            const track_pt_t *p = &n->track[(start + i) % KML_LIVE_TRACK_LEN];
            sb_printf(b, "        %.6f,%.6f,%.1f\n", p->lon, p->lat, p->alt_m);
        }
        sb_printf(b, "      </coordinates></LineString>\n    </Placemark>\n");
    }

    /* Line of sight from this station, like auto_rx's LOS line. */
    if (st) {
        sb_printf(b, "    <Placemark>\n      <name>LOS</name>\n      <styleUrl>#los</styleUrl>\n"
                     "      <LineString><tessellate>1</tessellate><altitudeMode>%s</altitudeMode><coordinates>\n"
                     "        %.6f,%.6f,%.1f\n        %.6f,%.6f,%.1f\n"
                     "      </coordinates></LineString>\n    </Placemark>\n",
                  n->have_alt ? "absolute" : "clampToGround",
                  st->lon, st->lat, st->alt_m, cur->lon, cur->lat, cur->alt_m);
    }
    sb_printf(b, "  </Folder>\n");
}

static int cmp_last_seen_desc(const void *a, const void *b)
{
    const live_node_t *x = a, *y = b;
    if (x->last_seen != y->last_seen) return x->last_seen < y->last_seen ? 1 : -1;
    return x->id < y->id ? -1 : (x->id > y->id);
}

char *kml_live_feed(const kml_live_station_t *st, time_t now, size_t *len)
{
    /* Snapshot under the lock, render without it: node_db_lookup takes
     * its own lock and the render can be slow for 256 nodes. */
    live_node_t *snap = malloc(sizeof(g_nodes));
    if (!snap) return NULL;
    pthread_mutex_lock(&g_lock);
    int count = g_count;
    memcpy(snap, g_nodes, sizeof(g_nodes[0]) * (size_t)count);
    pthread_mutex_unlock(&g_lock);
    qsort(snap, (size_t)count, sizeof(snap[0]), cmp_last_seen_desc);

    char gen[32];
    iso8601(gen, sizeof(gen), now);

    sbuf_t b = {0};
    sb_printf(&b,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
        "<Document>\n"
        "  <name>meshtastic-sniffer</name>\n"
        "  <open>1</open>\n"
        "  <description>%d node(s) with a position. Generated %s.</description>\n",
        count, gen);
    sb_printf(&b, "%s", KML_STYLES);

    if (st) {
        sb_printf(&b, "  <Placemark>\n    <name>");
        sb_xml(&b, (st->name && *st->name) ? st->name : "RX station");
        sb_printf(&b, "</name>\n    <description>meshtastic-sniffer receive station (gpsd)</description>\n"
                      "    <styleUrl>#station</styleUrl>\n"
                      "    <Point><altitudeMode>absolute</altitudeMode><coordinates>%.6f,%.6f,%.1f</coordinates></Point>\n"
                      "  </Placemark>\n",
                  st->lon, st->lat, st->alt_m);
    }
    for (int i = 0; i < count; ++i) write_node(&b, &snap[i], st, now);
    free(snap);
    sb_printf(&b, "</Document>\n</kml>\n");
    return sb_finish(&b, len);
}
