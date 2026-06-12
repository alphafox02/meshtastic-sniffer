/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: JSON output sink.
 *
 */

#include "cot.h"
#include "archive.h"
#include "feed.h"
#include "geofence.h"
#include "gpsd.h"
#include "mesh_decoders.h"
#include "meshtastic.h"
#include "node_db.h"
#include "options.h"

/* Forward decls for optional output sinks (their .c files compile to
 * stubs when the underlying lib isn't available). */
void mqtt_init(void);
void mqtt_publish(const char *json, size_t len);
void mqtt_shutdown(void);
void zmq_pub_init(void);
void zmq_pub_publish(const char *json, size_t len);
void zmq_pub_shutdown(void);
void web_publish_line(const char *json, size_t len);

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "net_util.h"

#define MAX_UDP_FEEDS  4

typedef struct {
    int                  fd;
    struct sockaddr_in   addr;
} udp_feed_t;

static udp_feed_t g_udp_feeds[MAX_UDP_FEEDS];
static int        g_udp_feed_count = 0;

/* ---- JSON writer (simple direct sprintf, not a full lib) ---- */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   first_field;
} jw_t;

static void jw_init(jw_t *j, char *buf, size_t cap) {
    j->buf = buf; j->cap = cap; j->len = 0; j->first_field = true;
}
static void jw_putc(jw_t *j, char c) {
    if (j->len + 1 < j->cap) j->buf[j->len++] = c;
}
static void jw_puts(jw_t *j, const char *s) {
    while (*s && j->len + 1 < j->cap) j->buf[j->len++] = *s++;
}
static void jw_printf(jw_t *j, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(j->buf + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < j->cap - j->len) j->len += (size_t)n;
}
static void jw_str_escaped(jw_t *j, const char *s) {
    jw_putc(j, '"');
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { jw_putc(j, '\\'); jw_putc(j, (char)c); }
        else if (c == '\n')        { jw_puts(j, "\\n"); }
        else if (c == '\r')        { jw_puts(j, "\\r"); }
        else if (c == '\t')        { jw_puts(j, "\\t"); }
        else if (c < 0x20)         { jw_printf(j, "\\u%04x", c); }
        else                       { jw_putc(j, (char)c); }
    }
    jw_putc(j, '"');
}
static void jw_field_name(jw_t *j, const char *name) {
    if (!j->first_field) jw_putc(j, ',');
    j->first_field = false;
    jw_str_escaped(j, name);
    jw_putc(j, ':');
}
static void jw_field_str(jw_t *j, const char *name, const char *value) {
    if (!value) return;
    jw_field_name(j, name);
    jw_str_escaped(j, value);
}
static void jw_field_u32(jw_t *j, const char *name, uint32_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%u", value);
}
static void jw_field_u64(jw_t *j, const char *name, uint64_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%llu", (unsigned long long)value);
}
static void jw_field_i32(jw_t *j, const char *name, int32_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%d", value);
}
static void jw_field_f32(jw_t *j, const char *name, float value) {
    jw_field_name(j, name);
    jw_printf(j, "%.4f", (double)value);
}
static void jw_field_f64(jw_t *j, const char *name, double value) {
    jw_field_name(j, name);
    jw_printf(j, "%.7f", value);
}
static void jw_field_bool(jw_t *j, const char *name, bool value) {
    jw_field_name(j, name);
    jw_puts(j, value ? "true" : "false");
}
static void jw_open(jw_t *j) { jw_putc(j, '{'); j->first_field = true; }
static void jw_close(jw_t *j) { jw_putc(j, '}'); j->first_field = false; }
static void jw_open_array(jw_t *j, const char *name) {
    jw_field_name(j, name); jw_putc(j, '['); j->first_field = true;
}
static void jw_close_array(jw_t *j) { jw_putc(j, ']'); j->first_field = false; }
static void jw_array_sep(jw_t *j) {
    if (!j->first_field) jw_putc(j, ',');
    j->first_field = false;
}

/* ---- JSON serializer for mesh_event_t ---- */

static void serialize_event(jw_t *j, const mesh_event_t *ev)
{
    jw_open(j);

    /* Top-level metadata */
    if (opt_station_id) jw_field_str(j, "station", opt_station_id);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double ts = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
    jw_field_f64(j, "ts", ts);

    /* Station GPS (when --gpsd is configured and a recent fix is in).
     * 30 s freshness window: gpsd updates ~1 Hz typical, so anything
     * older than that means we've lost fix and the position is stale. */
    if (opt_gpsd_endpoint) {
        double s_lat, s_lon, s_alt = 0, s_age = 0;
        if (gpsd_get_fix(&s_lat, &s_lon, &s_alt, &s_age) && s_age < 30.0) {
            jw_field_f64(j, "station_lat", s_lat);
            jw_field_f64(j, "station_lon", s_lon);
            if (s_alt != 0.0) jw_field_f32(j, "station_alt_m", (float)s_alt);
        }
    }

    /* Header */
    char id_buf[16];
    snprintf(id_buf, sizeof(id_buf), "!%08x", ev->header.from);
    jw_field_str(j, "from",       id_buf);

    snprintf(id_buf, sizeof(id_buf), "!%08x", ev->header.to);
    jw_field_str(j, "to",         id_buf);

    jw_field_u32(j, "packet_id",     ev->header.packet_id);
    jw_field_u32(j, "channel_hash",  ev->header.channel);  /* 1-byte routing hash from radio header */
    if (ev->slot_id >= 0)
        jw_field_u32(j, "slot_id",   (uint32_t)ev->slot_id); /* which decoder slot caught this */
    jw_field_u32(j, "hop_limit",     (uint32_t)ev->hop_limit);
    jw_field_u32(j, "hop_start",     (uint32_t)ev->hop_start);
    /* Upper byte of the relayer's node id; topology view can resolve
     * this to a known node when one is present in the keyset. */
    if (ev->header.relay_node)
        jw_field_u32(j, "relay_node", (uint32_t)ev->header.relay_node);
    if (ev->want_ack) jw_field_bool(j, "want_ack", true);
    if (ev->via_mqtt) jw_field_bool(j, "via_mqtt", true);
    if (ev->rssi_db != 0.0f) jw_field_f32(j, "rssi_db", ev->rssi_db);
    if (ev->snr_db  != 0.0f) jw_field_f32(j, "snr_db",  ev->snr_db);
    /* RF-quality telemetry. payload_crc_ok is emitted whenever a CRC
     * was present on the wire -- true if it passed, false if it failed.
     * Absent means no CRC field on the wire (implicit-header frame),
     * which is distinct from "checked and passed." cfo only when
     * |cfo| > 100 Hz so well-tuned radios don't spam noise. */
    if (ev->has_crc)
        jw_field_bool(j, "payload_crc_ok", ev->payload_crc_ok);
    /* fields_trusted is the honest answer to "should a consumer treat
     * the decoded from/to/packet_id/etc. as factual?" It is true only
     * when we have positive evidence the bytes were received intact:
     *   - the LoRa CRC field was present and verified, OR
     *   - the AES-CTR payload decrypted and parsed as a valid Data
     *     envelope (portnum was populated).
     * It is false for CRC-fail frames (bytes corrupted in transit, the
     * decoded fields are bit-errored) and for no-CRC frames whose
     * payload didn't decrypt (could be a real frame on an unknown PSK,
     * could be a noise pattern that passed the 5-bit header checksum
     * by luck -- 1/32 random chance -- and produced garbage bytes;
     * we can't tell without more evidence). Downstream consumers
     * displaying sightings on a map or counting unique nodes should
     * filter on fields_trusted == true to avoid surfacing
     * bit-corrupted phantoms as if they were real distinct nodes. */
    bool fields_trusted = (ev->has_crc && ev->payload_crc_ok)
                       || (!ev->has_crc && ev->decrypted);
    jw_field_bool(j, "fields_trusted", fields_trusted);
    if (ev->cfo_hz > 100.0f || ev->cfo_hz < -100.0f)
        jw_field_f32(j, "cfo_hz", ev->cfo_hz);
    /* Multilateration timestamp + accuracy class. Only emit when we
     * have a station name to attribute observations to (mlat is a
     * multi-station correlation; an unnamed sensor can't participate). */
    if (ev->station_t_ns && opt_station_id) {
        jw_field_u64(j, "station_t_ns",     ev->station_t_ns);
        jw_field_u32(j, "station_t_acc_ns", ev->station_t_acc_ns);
        /* TDOA anchor: absolute SDR sample index at the moment of
         * preamble lock for this frame, plus the SDR sample rate so
         * fusion can convert sample-count deltas across stations to
         * seconds. Only emit when populated; pre-lock or non-LoRa
         * frames leave both at 0. */
        if (ev->preamble_lock_sample_idx) {
            jw_field_u64(j, "preamble_lock_sample_idx",
                         ev->preamble_lock_sample_idx);
            /* Sub-sample timing offset, SDR-sample units. Convenience
             * field for consumers that want
             *     toa_sample = preamble_lock_sample_idx
             *                  + preamble_lock_sample_frac
             * The eventual cross-station IQ correlation produces the
             * authoritative sub-sample TOA; this field is the initial
             * fractional lock estimate from the decoder's RCTSL
             * estimator. */
            if (ev->preamble_lock_sample_frac != 0.0f) {
                jw_field_f32(j, "preamble_lock_sample_frac",
                             ev->preamble_lock_sample_frac);
            }
        }
        if (ev->sample_rate_sps) {
            jw_field_u64(j, "sample_rate_sps", ev->sample_rate_sps);
        }
        /* Software-lock TOA timestamp (CLOCK_REALTIME stamped at the
         * moment preamble lock was detected). Strictly earlier in the
         * pipeline than station_t_ns (which the dedup ring stamps
         * after frame demod completes). Fusion uses this as a
         * timestamp_class=software_lock source when present; it is
         * not a sample-derived GPSDO-grade TOA. */
        if (ev->preamble_lock_t_ns) {
            jw_field_u64(j, "preamble_lock_t_ns",
                         ev->preamble_lock_t_ns);
        }
    }

    /* Radio-layer fields: which physical preset/SF/CR/BW the frame arrived on.
     * Useful for operators bucketing traffic across multiple parallel demods. */
    if (ev->sf > 0) {
        jw_field_u32(j, "sf",    (uint32_t)ev->sf);
        jw_field_u32(j, "cr",    (uint32_t)ev->cr);
        jw_field_u32(j, "bw_hz", (uint32_t)ev->bw_hz);
        if (ev->freq_hz) jw_field_u64(j, "freq_hz", ev->freq_hz);
        if (ev->preset_name[0]) jw_field_str(j, "preset", ev->preset_name);
    }

    if (ev->decrypted) {
        if (ev->channel_name[0]) jw_field_str(j, "channel_name", ev->channel_name);
        jw_field_u32(j, "portnum",     ev->portnum);
        jw_field_str(j, "port_name",   mesh_port_name(ev->portnum));

        /* Per-port decoded fields */
        switch (ev->portnum) {
        case MESH_PORT_TEXT_MESSAGE: {
            char text[256];
            size_t n = ev->payload_len < sizeof(text) - 1 ? ev->payload_len : sizeof(text) - 1;
            memcpy(text, ev->payload, n); text[n] = 0;
            jw_field_str(j, "text", text);
            break;
        }
        case MESH_PORT_POSITION: {
            mesh_position_t p;
            if (mesh_decode_position(ev->payload, ev->payload_len, &p)) {
                if (p.have_lat)             jw_field_f64(j, "lat", p.lat_deg);
                if (p.have_lon)             jw_field_f64(j, "lon", p.lon_deg);
                if (p.have_alt)             jw_field_i32(j, "alt_m", p.altitude_m);
                if (p.have_alt_hae)         jw_field_i32(j, "alt_hae_m", p.altitude_hae_m);
                if (p.have_alt_geosep)      jw_field_i32(j, "alt_geoidal_sep_m", p.altitude_geoidal_separation_m);
                if (p.have_time)            jw_field_u32(j, "time", p.time);
                if (p.have_timestamp)       jw_field_u32(j, "timestamp", p.timestamp);
                if (p.timestamp_millis_adjust) jw_field_i32(j, "timestamp_ms_adj", p.timestamp_millis_adjust);
                if (p.location_source)      jw_field_u32(j, "loc_src", p.location_source);
                if (p.altitude_source)      jw_field_u32(j, "alt_src", p.altitude_source);
                if (p.pdop_x100)            jw_field_f64(j, "pdop", (double)p.pdop_x100 / 100.0);
                if (p.hdop_x100)            jw_field_f64(j, "hdop", (double)p.hdop_x100 / 100.0);
                if (p.vdop_x100)            jw_field_f64(j, "vdop", (double)p.vdop_x100 / 100.0);
                if (p.gps_accuracy_mm)      jw_field_u32(j, "gps_accuracy_mm", p.gps_accuracy_mm);
                if (p.have_ground_speed)    jw_field_u32(j, "speed_mps", p.ground_speed_mps);
                if (p.have_ground_track)    jw_field_f64(j, "track_deg", (double)p.ground_track_x100 / 100.0);
                if (p.fix_quality)          jw_field_u32(j, "fix_quality", p.fix_quality);
                if (p.fix_type)             jw_field_u32(j, "fix_type", p.fix_type);
                if (p.sats_in_view)         jw_field_u32(j, "sats", p.sats_in_view);
                if (p.sensor_id)            jw_field_u32(j, "sensor_id", p.sensor_id);
                if (p.next_update_s)        jw_field_u32(j, "next_update_s", p.next_update_s);
                if (p.seq_number)           jw_field_u32(j, "seq", p.seq_number);
                if (p.precision_bits)       jw_field_u32(j, "precision_bits", p.precision_bits);
                /* CoT republish for any positioned node, named via node_db cache. */
                cot_publish_position(ev, &p);
                /* Geofence transitions: ENTRY / EXIT events when this
                 * node crosses any configured polygon boundary. */
                if (p.have_lat && p.have_lon)
                    geofence_check(ev->header.from, p.lat_deg, p.lon_deg);
            }
            break;
        }
        case MESH_PORT_NODEINFO: {
            mesh_user_t u;
            if (mesh_decode_user(ev->payload, ev->payload_len, &u)) {
                if (u.id[0])         jw_field_str(j, "node_id",    u.id);
                if (u.long_name[0])  jw_field_str(j, "long_name",  u.long_name);
                if (u.short_name[0]) jw_field_str(j, "short_name", u.short_name);
                if (u.hw_model)      jw_field_u32(j, "hw_model",   u.hw_model);
                if (u.role)          jw_field_u32(j, "role",       u.role);
                if (u.is_licensed)   jw_field_bool(j, "licensed",  true);
                node_db_remember(ev->header.from, u.long_name, u.short_name,
                                 u.hw_model, u.role);
            }
            break;
        }
        case MESH_PORT_TELEMETRY: {
            mesh_telemetry_t t;
            if (mesh_decode_telemetry(ev->payload, ev->payload_len, &t)) {
                if (t.time_unix) jw_field_u32(j, "time", t.time_unix);
                if (t.have_device) {
                    jw_open_array(j, "device");
                    jw_array_sep(j); jw_putc(j, '{'); j->first_field = true;
                    jw_field_u32(j, "battery", t.battery_level);
                    jw_field_f32(j, "voltage", t.voltage);
                    jw_field_f32(j, "ch_util", t.channel_utilization);
                    jw_field_f32(j, "air_tx",  t.air_util_tx);
                    jw_field_u32(j, "uptime",  t.uptime_seconds);
                    jw_putc(j, '}');
                    jw_close_array(j);
                }
                if (t.have_environment) {
                    jw_open_array(j, "environment");
                    jw_array_sep(j); jw_putc(j, '{'); j->first_field = true;
                    if (t.temperature_c)              jw_field_f32(j, "temp_c",    t.temperature_c);
                    if (t.relative_humidity)          jw_field_f32(j, "humidity",  t.relative_humidity);
                    if (t.barometric_pressure_hpa)    jw_field_f32(j, "pressure",  t.barometric_pressure_hpa);
                    if (t.wind_speed)                 jw_field_f32(j, "wind_mps",  t.wind_speed);
                    jw_putc(j, '}');
                    jw_close_array(j);
                }
                if (t.have_power) {
                    jw_open_array(j, "power");
                    jw_array_sep(j); jw_putc(j, '{'); j->first_field = true;
                    if (t.ch1_voltage) jw_field_f32(j, "ch1_v", t.ch1_voltage);
                    if (t.ch1_current) jw_field_f32(j, "ch1_a", t.ch1_current);
                    jw_putc(j, '}');
                    jw_close_array(j);
                }
            }
            break;
        }
        case MESH_PORT_ATAK_PLUGIN: {
            mesh_atak_t a;
            if (mesh_decode_atak(ev->payload, ev->payload_len, &a)) {
                if (a.callsign[0])         jw_field_str(j, "atak_callsign", a.callsign);
                if (a.device_callsign[0])  jw_field_str(j, "atak_device", a.device_callsign);
                jw_field_str(j, "atak_team", mesh_atak_team_name(a.team));
                jw_field_str(j, "atak_role", mesh_atak_role_name(a.role));
                if (a.battery) jw_field_u32(j, "atak_battery", a.battery);
                if (a.kind == MESH_ATAK_PLI) {
                    if (a.have_lat) jw_field_f64(j, "lat", a.lat_deg);
                    if (a.have_lon) jw_field_f64(j, "lon", a.lon_deg);
                    if (a.altitude_hae_m)
                        jw_field_i32(j, "alt_hae_m", a.altitude_hae_m);
                    if (a.speed_mps)  jw_field_u32(j, "speed_mps", a.speed_mps);
                    if (a.course_deg) jw_field_u32(j, "course_deg", a.course_deg);
                } else if (a.kind == MESH_ATAK_CHAT) {
                    if (a.chat_message[0]) jw_field_str(j, "atak_chat", a.chat_message);
                    if (a.chat_to[0])      jw_field_str(j, "atak_chat_to", a.chat_to);
                    if (a.chat_to_callsign[0])
                        jw_field_str(j, "atak_chat_to_callsign", a.chat_to_callsign);
                }
                /* CoT multicast republish on PLI / DETAIL. */
                cot_publish_atak(ev, &a);
            }
            break;
        }
        case MESH_PORT_RANGE_TEST: {
            /* Range test packets are plain UTF-8 text payloads (typically a
             * monotonically incrementing "seq=N" sender stamp). Surface as
             * the same `text` field as TEXT_MESSAGE_APP -- combined with
             * rssi/snr/preset already in the line, that's everything an
             * operator needs for a range-test log. */
            char text[128];
            size_t n = ev->payload_len < sizeof(text) - 1 ? ev->payload_len : sizeof(text) - 1;
            memcpy(text, ev->payload, n); text[n] = 0;
            jw_field_str(j, "text", text);
            break;
        }
        case MESH_PORT_ROUTING: {
            mesh_routing_t r;
            if (mesh_decode_routing(ev->payload, ev->payload_len, &r)) {
                static const char *kinds[] = {"none","request","reply","error"};
                if (r.kind > 0 && r.kind < 4)
                    jw_field_str(j, "routing_kind", kinds[r.kind]);
                if (r.kind == MESH_ROUTING_ERROR)
                    jw_field_u32(j, "error_reason", r.error_reason);
                if (r.n_route > 0) {
                    jw_open_array(j, "route");
                    for (int i = 0; i < r.n_route; ++i) {
                        jw_array_sep(j);
                        char nid[16]; snprintf(nid, sizeof(nid), "!%08x", r.route[i]);
                        jw_str_escaped(j, nid);
                    }
                    jw_close_array(j);
                }
            }
            break;
        }
        case MESH_PORT_TRACEROUTE: {
            mesh_traceroute_t tr;
            if (mesh_decode_traceroute(ev->payload, ev->payload_len, &tr)) {
                if (tr.route_len) {
                    jw_open_array(j, "route");
                    for (int i = 0; i < tr.route_len; ++i) {
                        jw_array_sep(j);
                        char nid[16]; snprintf(nid, sizeof(nid), "!%08x", tr.route[i]);
                        jw_str_escaped(j, nid);
                    }
                    jw_close_array(j);
                }
            }
            break;
        }
        case MESH_PORT_WAYPOINT: {
            mesh_waypoint_t w;
            if (mesh_decode_waypoint(ev->payload, ev->payload_len, &w)) {
                if (w.id)            jw_field_u32(j, "waypoint_id", w.id);
                if (w.have_lat)      jw_field_f64(j, "lat", w.lat_deg);
                if (w.have_lon)      jw_field_f64(j, "lon", w.lon_deg);
                if (w.expire)        jw_field_u32(j, "expire", w.expire);
                if (w.locked_to)     jw_field_u32(j, "locked_to", w.locked_to);
                if (w.name[0])       jw_field_str(j, "wp_name", w.name);
                if (w.description[0])jw_field_str(j, "wp_desc", w.description);
                if (w.icon)          jw_field_u32(j, "wp_icon", w.icon);
            }
            break;
        }
        case MESH_PORT_NEIGHBORINFO: {
            mesh_neighborinfo_t ni;
            if (mesh_decode_neighborinfo(ev->payload, ev->payload_len, &ni)) {
                jw_field_u32(j, "neighbor_node_id", ni.node_id);
                if (ni.last_sent_by_id) jw_field_u32(j, "last_sent_by", ni.last_sent_by_id);
                if (ni.node_broadcast_interval_secs)
                    jw_field_u32(j, "broadcast_interval_s", ni.node_broadcast_interval_secs);
                if (ni.n_neighbors > 0) {
                    jw_open_array(j, "neighbors");
                    for (int i = 0; i < ni.n_neighbors; ++i) {
                        jw_array_sep(j); jw_putc(j, '{'); j->first_field = true;
                        char nid[16]; snprintf(nid, sizeof(nid), "!%08x", ni.neighbors[i].node_id);
                        jw_field_str(j, "id", nid);
                        if (ni.neighbors[i].snr_db != 0.0f)
                            jw_field_f32(j, "snr_db", ni.neighbors[i].snr_db);
                        jw_putc(j, '}');
                    }
                    jw_close_array(j);
                }
            }
            break;
        }
        case MESH_PORT_KEY_VERIFICATION: {
            mesh_keyverif_t kv;
            if (mesh_decode_keyverif(ev->payload, ev->payload_len, &kv)) {
                if (kv.remote_node_id) jw_field_u32(j, "kv_remote", kv.remote_node_id);
                if (kv.hash1_len)      jw_field_u32(j, "kv_hash1_len", (uint32_t)kv.hash1_len);
                if (kv.hash2_len)      jw_field_u32(j, "kv_hash2_len", (uint32_t)kv.hash2_len);
            }
            break;
        }
        case MESH_PORT_MAP_REPORT: {
            mesh_mapreport_t mr;
            if (mesh_decode_mapreport(ev->payload, ev->payload_len, &mr)) {
                if (mr.long_name[0])  jw_field_str(j, "long_name", mr.long_name);
                if (mr.short_name[0]) jw_field_str(j, "short_name", mr.short_name);
                if (mr.firmware_version[0]) jw_field_str(j, "firmware", mr.firmware_version);
                if (mr.role)         jw_field_u32(j, "role", mr.role);
                if (mr.hw_model)     jw_field_u32(j, "hw_model", mr.hw_model);
                if (mr.region)       jw_field_u32(j, "region", mr.region);
                if (mr.modem_preset) jw_field_u32(j, "sender_preset", mr.modem_preset);
                if (mr.have_lat)     jw_field_f64(j, "lat", mr.lat_deg);
                if (mr.have_lon)     jw_field_f64(j, "lon", mr.lon_deg);
                if (mr.altitude_m)   jw_field_i32(j, "alt_m", mr.altitude_m);
                if (mr.num_online_local_nodes)
                    jw_field_u32(j, "online_nodes", mr.num_online_local_nodes);
                /* MAP_REPORTs carry node identity; cache for CoT callsigns. */
                node_db_remember(ev->header.from, mr.long_name, mr.short_name,
                                 mr.hw_model, mr.role);
            }
            break;
        }
        case MESH_PORT_ADMIN: {
            mesh_admin_t a;
            if (mesh_decode_admin(ev->payload, ev->payload_len, &a)) {
                if (a.variant_field) jw_field_u32(j, "admin_variant", a.variant_field);
                if (a.has_session_passkey) jw_field_bool(j, "admin_session", true);
            }
            break;
        }
        case MESH_PORT_REMOTE_HARDWARE: {
            mesh_remote_hw_t h;
            if (mesh_decode_remote_hw(ev->payload, ev->payload_len, &h)) {
                if (h.type) jw_field_u32(j, "hw_type", h.type);
                if (h.gpio_mask)  jw_field_u32(j, "hw_gpio_mask",  (uint32_t)h.gpio_mask);
                if (h.gpio_value) jw_field_u32(j, "hw_gpio_value", (uint32_t)h.gpio_value);
                if (h.txid)       jw_field_u32(j, "hw_txid", h.txid);
            }
            break;
        }
        case MESH_PORT_DETECTION_SENSOR: {
            mesh_detection_t d;
            if (mesh_decode_detection(ev->payload, ev->payload_len, &d)) {
                if (d.text[0]) jw_field_str(j, "detection_text", d.text);
            }
            break;
        }
        case MESH_PORT_PAXCOUNTER: {
            mesh_paxcounter_t pc;
            if (mesh_decode_paxcounter(ev->payload, ev->payload_len, &pc)) {
                jw_field_u32(j, "pax_wifi",   pc.wifi);
                jw_field_u32(j, "pax_ble",    pc.ble);
                jw_field_u32(j, "pax_uptime_s", pc.uptime_s);
            }
            break;
        }
        case MESH_PORT_STORE_FORWARD: {
            mesh_storeforward_t sf;
            if (mesh_decode_storeforward(ev->payload, ev->payload_len, &sf)) {
                const char *rr = mesh_storeforward_rr_name(sf.rr);
                if (rr) jw_field_str(j, "sf_rr", rr);
                else    jw_field_u32(j, "sf_rr_id", sf.rr);
                if (sf.have_stats) {
                    jw_field_u32(j, "sf_total",     sf.stats_total);
                    jw_field_u32(j, "sf_history",   sf.stats_history);
                    jw_field_u32(j, "sf_max",       sf.stats_max);
                    jw_field_u32(j, "sf_uptime_s",  sf.stats_up_time_s);
                    jw_field_u32(j, "sf_requests",  sf.stats_requests);
                }
                if (sf.have_history) {
                    jw_field_u32(j, "sf_hist_count",  sf.hist_count);
                    jw_field_u32(j, "sf_hist_window_s", sf.hist_window_s);
                }
            }
            break;
        }
        }
    } else {
        jw_field_bool(j, "decrypted", false);
    }

    jw_close(j);
    jw_putc(j, '\n');
    if (j->len < j->cap) j->buf[j->len] = 0;
}

/* ---- Output sinks ---- */

static void emit_to_stdout(const char *line, size_t len)
{
    /* Stdout is line-buffered so write+flush. */
    fwrite(line, 1, len, stdout);
    fflush(stdout);
}

static void emit_to_udp(const char *line, size_t len)
{
    for (int i = 0; i < g_udp_feed_count; ++i) {
        sendto(g_udp_feeds[i].fd, line, len, MSG_DONTWAIT,
               (struct sockaddr *)&g_udp_feeds[i].addr,
               sizeof(g_udp_feeds[i].addr));
    }
}

void feed_init(void)
{
    /* Open one UDP socket per --feed=HOST:PORT. */
    for (int i = 0; i < FEED_MAX && opt_feed_endpoint[i]; ++i) {
        if (g_udp_feed_count >= MAX_UDP_FEEDS) break;
        char *colon = strchr(opt_feed_endpoint[i], ':');
        if (!colon) continue;
        size_t hostlen = (size_t)(colon - opt_feed_endpoint[i]);
        char host[64];
        if (hostlen >= sizeof(host)) hostlen = sizeof(host) - 1;
        memcpy(host, opt_feed_endpoint[i], hostlen);
        host[hostlen] = 0;
        int port = atoi(colon + 1);
        if (port <= 0) continue;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in *a = &g_udp_feeds[g_udp_feed_count].addr;
        memset(a, 0, sizeof(*a));
        a->sin_family = AF_INET;
        a->sin_port   = htons((uint16_t)port);
        if (resolve_host_ipv4(host, &a->sin_addr) < 0) { close(fd); continue; }

        g_udp_feeds[g_udp_feed_count].fd = fd;
        g_udp_feed_count++;
        if (verbose) fprintf(stderr, "feed: UDP -> %s:%d\n", host, port);
    }
    mqtt_init();
    zmq_pub_init();
    cot_init();
}

void feed_shutdown(void)
{
    for (int i = 0; i < g_udp_feed_count; ++i) close(g_udp_feeds[i].fd);
    g_udp_feed_count = 0;
    mqtt_shutdown();
    zmq_pub_shutdown();
    cot_shutdown();
}

void feed_publish_event(const mesh_event_t *ev)
{
    if (!ev) return;
    /* --trusted-only suppresses untrusted events from every publishing sink.
     * Stats counters (in main.c) tally upstream of this so the heartbeat
     * still shows the true LoRa frames / no-CRC count -- operators can see
     * how much RF noise-admit is being filtered out. The decoder path is
     * unchanged; only publication is gated. */
    if (opt_trusted_only) {
        bool trusted = (ev->has_crc && ev->payload_crc_ok)
                    || (!ev->has_crc && ev->decrypted);
        if (!trusted) return;
    }
    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    serialize_event(&j, ev);
    emit_to_stdout(buf, j.len);
    if (g_udp_feed_count) emit_to_udp(buf, j.len);
    mqtt_publish(buf, j.len);
    zmq_pub_publish(buf, j.len);
    web_publish_line(buf, j.len);
    archive_publish(buf, j.len);
}
