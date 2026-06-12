/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: CoT (Cursor-on-Target) XML multicast republish.
 *
 */

#include "cot.h"
#include "node_db.h"
#include "options.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "net_util.h"

/* Endpoint state -- mutable at runtime via cot_set_endpoint(). */
static int                g_fd = -1;
static struct sockaddr_in g_dst;
static bool               g_active = false;
static pthread_mutex_t    g_lock = PTHREAD_MUTEX_INITIALIZER;

/* xml_escape copies src to dst replacing XML metacharacters with their
 * entity forms. NUL-terminates and truncates rather than overflowing.
 * Callers should size dst generously -- worst case is '&' expanding to
 * "&amp;" (5x). Source strings can be arbitrary user-controlled bytes
 * (remote NODEINFO long_name, operator station-id, channel names);
 * unescaped insertion into CoT XML attributes/text would corrupt the
 * wire format for the ATAK receiver and in the worst case inject extra
 * XML structure. */
static void xml_escape(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return;
    size_t di = 0;
    if (!src) { dst[0] = 0; return; }
    for (; *src && di + 1 < dst_sz; ++src) {
        const char *ent = NULL;
        size_t      el = 0;
        switch ((unsigned char)*src) {
            case '<':  ent = "&lt;";   el = 4; break;
            case '>':  ent = "&gt;";   el = 4; break;
            case '&':  ent = "&amp;";  el = 5; break;
            case '"':  ent = "&quot;"; el = 6; break;
            case '\'': ent = "&apos;"; el = 6; break;
        }
        if (ent) {
            if (di + el + 1 > dst_sz) break;
            memcpy(dst + di, ent, el);
            di += el;
        } else {
            dst[di++] = *src;
        }
    }
    dst[di] = 0;
}

int cot_set_endpoint(const char *host, int port)
{
    pthread_mutex_lock(&g_lock);

    /* Disable. */
    if (!host || !*host || port <= 0) {
        if (g_fd >= 0) { close(g_fd); g_fd = -1; }
        g_active = false;
        pthread_mutex_unlock(&g_lock);
        if (verbose) fprintf(stderr, "cot: disabled\n");
        return 0;
    }

    /* Open / reopen the socket. */
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    g_active = false;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    unsigned char ttl = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)port);
    if (resolve_host_ipv4(host, &dst.sin_addr) < 0) {
        close(fd);
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    g_fd     = fd;
    g_dst    = dst;
    g_active = true;
    pthread_mutex_unlock(&g_lock);

    fprintf(stderr, "cot: multicast %s:%d\n", host, port);
    return 0;
}

void cot_init(void)
{
    if (!opt_cot_multicast) return;
    char  host[64];
    int   port = 6969;
    const char *colon = strchr(opt_cot_multicast, ':');
    size_t hlen = colon ? (size_t)(colon - opt_cot_multicast) : strlen(opt_cot_multicast);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, opt_cot_multicast, hlen);
    host[hlen] = 0;
    if (colon) port = atoi(colon + 1);
    if (port <= 0) port = 6969;
    cot_set_endpoint(host, port);
}

void cot_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    g_active = false;
    pthread_mutex_unlock(&g_lock);
}

static void send_xml(const char *xml, size_t len)
{
    pthread_mutex_lock(&g_lock);
    if (g_active && g_fd >= 0) {
        sendto(g_fd, xml, len, MSG_DONTWAIT,
               (struct sockaddr *)&g_dst, sizeof(g_dst));
    }
    pthread_mutex_unlock(&g_lock);
}

static void iso8601_now(char *out, size_t out_size, int seconds_from_now)
{
    struct timeval tv; gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec + seconds_from_now;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    snprintf(out, out_size, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(tv.tv_usec / 1000));
}

/* Map ATAK Role enum to a CoT type with subkind. Friendly + ground unit
 * always; subkind specialises medic / sniper / HQ where known. */
static const char *cot_type_for_atak(const mesh_atak_t *atak)
{
    switch (atak->role) {
    case 4:  return "a-f-G-U-C-M";   /* Medic */
    case 3:  return "a-f-G-U-C-I";   /* Sniper */
    case 2:  return "a-f-G-U-C-H";   /* HQ */
    default: return "a-f-G-U-C";
    }
}

void cot_publish_atak(const mesh_event_t *ev, const mesh_atak_t *atak)
{
    if (!ev || !atak) return;
    if (!g_active) return;

    /* DETAIL = full uncompressed CoT XML, just forward. */
    if (atak->kind == MESH_ATAK_DETAIL && atak->detail_xml && atak->detail_xml_len > 0) {
        send_xml((const char *)atak->detail_xml, atak->detail_xml_len);
        return;
    }
    if (atak->kind != MESH_ATAK_PLI) return;
    if (!atak->have_lat || !atak->have_lon) return;

    char now[40], stale[40];
    iso8601_now(now,   sizeof(now),    0);
    iso8601_now(stale, sizeof(stale), 60);

    /* UID format: MESH[-<station>]-<callsign-or-!nodeid>. Multi-station
     * deployments set --station-id so CoT UIDs don't collide across rxers.
     * station-id and callsign are user-controlled (operator config, remote
     * NODEINFO long_name); escape both before XML insertion to keep the
     * CoT wire format honest even when a node names itself "<script>". */
    const char *station = (opt_station_id && *opt_station_id) ? opt_station_id : NULL;
    char esc_station[128] = "";
    char esc_callsign[256] = "";
    if (station) xml_escape(esc_station, sizeof(esc_station), station);
    xml_escape(esc_callsign, sizeof(esc_callsign), atak->callsign);
    char uid[512];
    if (esc_callsign[0]) {
        if (esc_station[0]) snprintf(uid, sizeof(uid), "MESH-%s-%s", esc_station, esc_callsign);
        else                snprintf(uid, sizeof(uid), "MESH-%s",    esc_callsign);
    } else {
        if (esc_station[0]) snprintf(uid, sizeof(uid), "MESH-%s-!%08x", esc_station, ev->header.from);
        else                snprintf(uid, sizeof(uid), "MESH-!%08x",    ev->header.from);
    }

    char xml[1536];
    int n = snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<event version=\"2.0\" uid=\"%s\" type=\"%s\" time=\"%s\" start=\"%s\" stale=\"%s\" how=\"m-g\">"
        "<point lat=\"%.7f\" lon=\"%.7f\" hae=\"%d\" ce=\"15\" le=\"15\"/>"
        "<detail>"
        "<contact callsign=\"%s\"/>"
        "<__group name=\"%s\" role=\"%s\"/>"
        "<track speed=\"%u\" course=\"%u\"/>"
        "<status battery=\"%u\"/>"
        "<remarks>meshtastic-sniffer atak/from=!%08x</remarks>"
        "</detail>"
        "</event>",
        uid, cot_type_for_atak(atak), now, now, stale,
        atak->lat_deg, atak->lon_deg, atak->altitude_hae_m,
        esc_callsign[0] ? esc_callsign : uid,
        mesh_atak_team_name(atak->team), mesh_atak_role_name(atak->role),
        atak->speed_mps, atak->course_deg, atak->battery,
        ev->header.from);
    if (n > 0) send_xml(xml, (size_t)n);
}

void cot_publish_position(const mesh_event_t *ev, const mesh_position_t *pos)
{
    if (!ev || !pos) return;
    if (!g_active) return;
    if (!pos->have_lat || !pos->have_lon) return;

    /* Look up callsign from NODEINFO cache; fall back to !nodeid.
     * long_name is whatever the remote node set in its NODEINFO --
     * arbitrary user-controlled bytes, must be entity-escaped before
     * landing in CoT XML attributes/text. */
    node_record_t rec;
    char callsign_raw[NODE_DB_LONG_NAME];
    if (node_db_lookup(ev->header.from, &rec) && rec.long_name[0]) {
        strncpy(callsign_raw, rec.long_name, sizeof(callsign_raw) - 1);
        callsign_raw[sizeof(callsign_raw) - 1] = 0;
    } else {
        snprintf(callsign_raw, sizeof(callsign_raw), "!%08x", ev->header.from);
    }
    char callsign[sizeof(callsign_raw) * 6];
    xml_escape(callsign, sizeof(callsign), callsign_raw);

    char now[40], stale[40];
    iso8601_now(now,   sizeof(now),    0);
    iso8601_now(stale, sizeof(stale), 300);

    const char *station = (opt_station_id && *opt_station_id) ? opt_station_id : NULL;
    char esc_station[128] = "";
    if (station) xml_escape(esc_station, sizeof(esc_station), station);
    char uid[512];
    if (esc_station[0]) snprintf(uid, sizeof(uid), "MESH-%s-!%08x", esc_station, ev->header.from);
    else                snprintf(uid, sizeof(uid), "MESH-!%08x", ev->header.from);

    /* Build remarks string with all the operator-relevant context: which
     * preset/SF/CR/BW the frame came in on, RSSI/SNR if available, hop info,
     * and channel name when decryption matched. Lets a CoT consumer (ATAK)
     * tell traffic on different physical pipes apart. Build in plain text
     * first, then entity-escape the whole thing as one piece before the
     * XML snprintf -- preset_name and channel_name are operator/key-spec
     * controlled and have shown up with unusual characters in the wild. */
    char remarks_raw[384];
    int rn = 0;
    rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                   "from=!%08x", ev->header.from);
    if (ev->preset_name[0])
        rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                       " preset=%s", ev->preset_name);
    if (ev->sf > 0)
        rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                       " SF%d/CR4-%d/BW%d", ev->sf, ev->cr, ev->bw_hz);
    if (ev->channel_name[0])
        rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                       " ch=%s", ev->channel_name);
    if (ev->rssi_db != 0.0f || ev->snr_db != 0.0f)
        rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                       " RSSI=%.1f SNR=%.1f", (double)ev->rssi_db, (double)ev->snr_db);
    if (ev->hop_limit || ev->hop_start)
        rn += snprintf(remarks_raw + rn, sizeof(remarks_raw) - rn,
                       " hop=%d/%d", ev->hop_limit, ev->hop_start);
    (void)rn;
    char remarks[sizeof(remarks_raw) * 6];
    xml_escape(remarks, sizeof(remarks), remarks_raw);

    char xml[2048];
    int n = snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<event version=\"2.0\" uid=\"%s\" type=\"a-f-G-U-C\" time=\"%s\" start=\"%s\" stale=\"%s\" how=\"m-g\">"
        "<point lat=\"%.7f\" lon=\"%.7f\" hae=\"%d\" ce=\"50\" le=\"50\"/>"
        "<detail>"
        "<contact callsign=\"%s\"/>"
        "<__group name=\"meshtastic\" role=\"Team Member\"/>"
        "<track speed=\"%u\" course=\"%u\"/>"
        "<remarks>%s</remarks>"
        "</detail>"
        "</event>",
        uid, now, now, stale,
        pos->lat_deg, pos->lon_deg, pos->have_alt ? pos->altitude_m : 0,
        callsign,
        pos->ground_speed_mps, pos->ground_track_x100 / 100u,
        remarks);
    if (n > 0) send_xml(xml, (size_t)n);
}
