/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: per-port protobuf decoders.
 *
 * Field numbers and types come from the Meshtastic .proto files
 * (meshtastic/mesh.proto, telemetry.proto). Each decoder is a tag
 * switch over the input buffer; unknown fields are skipped.
 *
 */

#include "mesh_decoders.h"
#include "protobuf.h"

#include <math.h>
#include <string.h>

static void copy_str(char *dst, size_t dst_size, const uint8_t *src, size_t src_len)
{
    if (src_len >= dst_size) src_len = dst_size - 1;
    memcpy(dst, src, src_len);
    dst[src_len] = 0;
}

static float u32_as_float(uint32_t v)
{
    float f;
    memcpy(&f, &v, 4);
    return f;
}

/* ---- POSITION_APP -- meshtastic.Position ---- */
bool mesh_decode_position(const uint8_t *buf, size_t len, mesh_position_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;

    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        switch (fld) {
        case 1: { uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->lat_deg  = (double)pb_zigzag32((uint32_t)v) * 1e-7;
                  out->have_lat = true; break; }
        case 2: { uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->lon_deg  = (double)pb_zigzag32((uint32_t)v) * 1e-7;
                  out->have_lon = true; break; }
        case 3: { uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->altitude_m = (int32_t)v;
                  out->have_alt = true; break; }
        case 9: { uint32_t v; if (!pb_read_fixed32(&p, end, &v)) return false;
                  out->time_unix = v; break; }
        case 5: { uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->location_source = (uint32_t)v; break; }
        case 12:{ uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->sats_in_view = (uint32_t)v; break; }
        case 15:{ uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->pdop_x100 = (uint32_t)v; break; }
        case 16:{ uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->ground_speed_mps = (uint32_t)v; break; }
        case 17:{ uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->ground_track = (uint32_t)v; break; }
        case 18:{ uint64_t v; if (!pb_read_varint(&p, end, &v)) return false;
                  out->precision_bits = (uint32_t)v; break; }
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->have_lat || out->have_lon || out->time_unix != 0;
}

/* ---- NODEINFO_APP -- meshtastic.User ---- */
bool mesh_decode_user(const uint8_t *buf, size_t len, mesh_user_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->id, sizeof(out->id), bp, blen); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->long_name, sizeof(out->long_name), bp, blen); break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->short_name, sizeof(out->short_name), bp, blen); break;
        case 4: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                if (blen == 6) { memcpy(out->macaddr, bp, 6); out->have_macaddr = true; }
                break;
        case 5: if (!pb_read_varint(&p, end, &v)) return false; out->hw_model = (uint32_t)v; break;
        case 6: if (!pb_read_varint(&p, end, &v)) return false; out->is_licensed = v != 0; break;
        case 7: if (!pb_read_varint(&p, end, &v)) return false; out->role = (uint32_t)v; break;
        case 8: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                if (blen <= sizeof(out->public_key)) { memcpy(out->public_key, bp, blen); out->have_public_key = true; }
                break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->id[0] || out->long_name[0] || out->short_name[0];
}

/* ---- TELEMETRY_APP -- meshtastic.Telemetry (oneof) ----
 *
 * Top level fields:
 *   1: time (fixed32)
 *   2: device_metrics (DeviceMetrics)
 *   3: environment_metrics (EnvironmentMetrics)
 *   4: air_quality_metrics
 *   5: power_metrics (PowerMetrics)
 *   6: local_stats
 */

static void parse_device_metrics(const uint8_t *buf, size_t len, mesh_telemetry_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        uint32_t f32; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return; out->battery_level = (uint32_t)v; break;
        case 2: if (!pb_read_fixed32(&p, end, &f32)) return; out->voltage = u32_as_float(f32); break;
        case 3: if (!pb_read_fixed32(&p, end, &f32)) return; out->channel_utilization = u32_as_float(f32); break;
        case 4: if (!pb_read_fixed32(&p, end, &f32)) return; out->air_util_tx = u32_as_float(f32); break;
        case 5: if (!pb_read_varint(&p, end, &v)) return; out->uptime_seconds = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
    out->have_device = true;
}

static void parse_env_metrics(const uint8_t *buf, size_t len, mesh_telemetry_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        uint32_t f32;
        switch (fld) {
        case 1: if (!pb_read_fixed32(&p, end, &f32)) return; out->temperature_c           = u32_as_float(f32); break;
        case 2: if (!pb_read_fixed32(&p, end, &f32)) return; out->relative_humidity       = u32_as_float(f32); break;
        case 3: if (!pb_read_fixed32(&p, end, &f32)) return; out->barometric_pressure_hpa = u32_as_float(f32); break;
        case 4: if (!pb_read_fixed32(&p, end, &f32)) return; out->gas_resistance          = u32_as_float(f32); break;
        case 5: if (!pb_read_fixed32(&p, end, &f32)) return; out->voltage_env             = u32_as_float(f32); break;
        case 6: if (!pb_read_fixed32(&p, end, &f32)) return; out->current                 = u32_as_float(f32); break;
        case 7: if (!pb_read_fixed32(&p, end, &f32)) return; out->iaq                     = u32_as_float(f32); break;
        case 8: if (!pb_read_fixed32(&p, end, &f32)) return; out->distance_mm             = u32_as_float(f32); break;
        case 9: if (!pb_read_fixed32(&p, end, &f32)) return; out->lux                     = u32_as_float(f32); break;
        case 10:if (!pb_read_fixed32(&p, end, &f32)) return; out->white_lux               = u32_as_float(f32); break;
        case 11:if (!pb_read_fixed32(&p, end, &f32)) return; out->ir_lumens               = u32_as_float(f32); break;
        case 12:if (!pb_read_fixed32(&p, end, &f32)) return; out->uv_lux                  = u32_as_float(f32); break;
        case 13:if (!pb_read_fixed32(&p, end, &f32)) return; out->wind_direction          = u32_as_float(f32); break;
        case 14:if (!pb_read_fixed32(&p, end, &f32)) return; out->wind_speed              = u32_as_float(f32); break;
        case 15:if (!pb_read_fixed32(&p, end, &f32)) return; out->wind_gust               = u32_as_float(f32); break;
        case 16:if (!pb_read_fixed32(&p, end, &f32)) return; out->wind_lull               = u32_as_float(f32); break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
    out->have_environment = true;
}

static void parse_power_metrics(const uint8_t *buf, size_t len, mesh_telemetry_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        uint32_t f32;
        switch (fld) {
        case 1: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch1_voltage = u32_as_float(f32); break;
        case 2: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch1_current = u32_as_float(f32); break;
        case 3: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch2_voltage = u32_as_float(f32); break;
        case 4: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch2_current = u32_as_float(f32); break;
        case 5: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch3_voltage = u32_as_float(f32); break;
        case 6: if (!pb_read_fixed32(&p, end, &f32)) return; out->ch3_current = u32_as_float(f32); break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
    out->have_power = true;
}

bool mesh_decode_telemetry(const uint8_t *buf, size_t len, mesh_telemetry_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    bool any = false;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return any;
        const uint8_t *bp; size_t blen;
        switch (fld) {
        case 1: { uint32_t v; if (!pb_read_fixed32(&p, end, &v)) return any;
                  out->time_unix = v; any = true; break; }
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return any;
                parse_device_metrics(bp, blen, out); any = true; break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return any;
                parse_env_metrics(bp, blen, out); any = true; break;
        case 5: if (!pb_read_length(&p, end, &bp, &blen)) return any;
                parse_power_metrics(bp, blen, out); any = true; break;
        default: if (!pb_skip_value(&p, end, wt)) return any; break;
        }
    }
    return any;
}

/* RouteDiscovery sub-message: repeated fixed32 route = 1. We pull the
 * node-ID path; per-hop SNRs (fields 2/4) and reverse path (field 3)
 * skipped for now. */
static void parse_route_discovery(const uint8_t *buf, size_t len, mesh_routing_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        if (fld == 1) {
            /* Repeated fixed32 -- can be packed (length-delim block of fixed32s)
             * or unpacked (one tag per element). Handle both. */
            if (wt == 5) {
                uint32_t f;
                if (!pb_read_fixed32(&p, end, &f)) return;
                if (out->n_route < (int)(sizeof(out->route)/sizeof(out->route[0])))
                    out->route[out->n_route++] = f;
            } else if (wt == 2) {
                const uint8_t *bp; size_t blen;
                if (!pb_read_length(&p, end, &bp, &blen)) return;
                while (bp + 4 <= buf + len &&
                       out->n_route < (int)(sizeof(out->route)/sizeof(out->route[0])) &&
                       blen >= 4) {
                    uint32_t f = (uint32_t)bp[0] | ((uint32_t)bp[1] << 8) |
                                 ((uint32_t)bp[2] << 16) | ((uint32_t)bp[3] << 24);
                    out->route[out->n_route++] = f;
                    bp += 4; blen -= 4;
                }
            } else {
                if (!pb_skip_value(&p, end, wt)) return;
            }
        } else {
            if (!pb_skip_value(&p, end, wt)) return;
        }
    }
}

/* ---- ROUTING_APP -- meshtastic.Routing ---- */
bool mesh_decode_routing(const uint8_t *buf, size_t len, mesh_routing_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                out->kind = MESH_ROUTING_REQUEST;
                parse_route_discovery(bp, blen, out); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                out->kind = MESH_ROUTING_REPLY;
                parse_route_discovery(bp, blen, out); break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false;
                out->kind = MESH_ROUTING_ERROR;
                out->error_reason = (uint32_t)v;
                out->have_error = true; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->kind != MESH_ROUTING_NONE;
}

/* ---- WAYPOINT_APP -- meshtastic.Waypoint ---- */
bool mesh_decode_waypoint(const uint8_t *buf, size_t len, mesh_waypoint_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->id = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false;
                out->lat_deg = (double)pb_zigzag32((uint32_t)v) * 1e-7; out->have_lat = true; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false;
                out->lon_deg = (double)pb_zigzag32((uint32_t)v) * 1e-7; out->have_lon = true; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->expire = (uint32_t)v; break;
        case 5: if (!pb_read_varint(&p, end, &v)) return false; out->locked_to = (uint32_t)v; break;
        case 6: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->name, sizeof(out->name), bp, blen); break;
        case 7: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->description, sizeof(out->description), bp, blen); break;
        case 8: if (!pb_read_varint(&p, end, &v)) return false; out->icon = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->have_lat || out->have_lon || out->name[0];
}

/* ---- NEIGHBORINFO_APP -- meshtastic.NeighborInfo ---- */
static void parse_one_neighbor(const uint8_t *buf, size_t len, mesh_neighbor_t *n)
{
    memset(n, 0, sizeof(*n));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt; uint64_t v;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return; n->node_id = (uint32_t)v; break;
        case 2: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return;
                  n->snr_db = u32_as_float(f); break; }
        case 3: if (!pb_read_varint(&p, end, &v)) return; n->last_rx_time = (uint32_t)v; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return; n->node_broadcast_interval_secs = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

bool mesh_decode_neighborinfo(const uint8_t *buf, size_t len, mesh_neighborinfo_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->node_id = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false; out->last_sent_by_id = (uint32_t)v; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false; out->node_broadcast_interval_secs = (uint32_t)v; break;
        case 4: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                if (out->n_neighbors < 16)
                    parse_one_neighbor(bp, blen, &out->neighbors[out->n_neighbors++]);
                break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->node_id != 0 || out->n_neighbors > 0;
}

/* ---- KEY_VERIFICATION_APP -- subset of meshtastic.KeyVerification ----
 *
 * Only the metadata: nonce, remote_node_id, hash sizes. We do not
 * surface the hash bytes -- they could be used to fingerprint a
 * verification exchange, and the JSON feed crosses trust boundaries. */
bool mesh_decode_keyverif(const uint8_t *buf, size_t len, mesh_keyverif_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->nonce = v; break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false; out->hash1_len = (int)blen; break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return false; out->hash2_len = (int)blen; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->remote_node_id = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->nonce != 0 || out->remote_node_id != 0;
}

/* ---- MAP_REPORT_APP -- meshtastic.MapReport ---- */
bool mesh_decode_mapreport(const uint8_t *buf, size_t len, mesh_mapreport_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen; uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->long_name, sizeof(out->long_name), bp, blen); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->short_name, sizeof(out->short_name), bp, blen); break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false; out->role = (uint32_t)v; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->hw_model = (uint32_t)v; break;
        case 5: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->firmware_version, sizeof(out->firmware_version), bp, blen); break;
        case 6: if (!pb_read_varint(&p, end, &v)) return false; out->region = (uint32_t)v; break;
        case 7: if (!pb_read_varint(&p, end, &v)) return false; out->modem_preset = (uint32_t)v; break;
        case 8: if (!pb_read_varint(&p, end, &v)) return false; out->has_default_channel = (uint32_t)v; break;
        case 9: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->lat_deg = (double)pb_zigzag32(f) * 1e-7; out->have_lat = true; break; }
        case 10:{ uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->lon_deg = (double)pb_zigzag32(f) * 1e-7; out->have_lon = true; break; }
        case 11:if (!pb_read_varint(&p, end, &v)) return false; out->altitude_m = (int32_t)v; break;
        case 12:if (!pb_read_varint(&p, end, &v)) return false; out->position_precision = (uint32_t)v; break;
        case 13:if (!pb_read_varint(&p, end, &v)) return false; out->num_online_local_nodes = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->long_name[0] || out->have_lat;
}

/* ---- ADMIN_APP -- subset of meshtastic.AdminMessage ----
 *
 * AdminMessage's payload_variant is a oneof with ~40 possible legs.
 * We surface only which field number was present, so observers can
 * see "an admin RPC of type N happened" without us decoding every
 * variant exhaustively. */
bool mesh_decode_admin(const uint8_t *buf, size_t len, mesh_admin_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        if (fld == 101) { /* session_passkey */
            const uint8_t *bp; size_t blen;
            if (!pb_read_length(&p, end, &bp, &blen)) return false;
            out->has_session_passkey = blen > 0;
        } else {
            /* Latch the first non-session-passkey field number we see. */
            if (out->variant_field == 0 && fld != 0) out->variant_field = fld;
            if (!pb_skip_value(&p, end, wt)) return false;
        }
    }
    return out->variant_field != 0 || out->has_session_passkey;
}

/* ---- ATAK_PLUGIN (port 72) -- meshtastic.atak.TAKPacket ---- */

const char *mesh_atak_team_name(int team)
{
    static const char *names[] = {
        "Unspecified","White","Yellow","Orange","Magenta","Red","Maroon","Purple",
        "DarkBlue","Blue","Cyan","Teal","Green","DarkGreen","Brown"
    };
    if (team < 0 || team >= (int)(sizeof(names)/sizeof(names[0]))) return "Unspecified";
    return names[team];
}

const char *mesh_atak_role_name(int role)
{
    static const char *names[] = {
        "TeamMember","TeamLead","HQ","Sniper","Medic","ForwardObserver",
        "RTO","K9"
    };
    if (role < 0 || role >= (int)(sizeof(names)/sizeof(names[0]))) return "Unknown";
    return names[role];
}

static void parse_contact(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        const uint8_t *bp; size_t blen;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return;
                copy_str(out->callsign, sizeof(out->callsign), bp, blen); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return;
                copy_str(out->device_callsign, sizeof(out->device_callsign), bp, blen); break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

static void parse_group(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt; uint64_t v;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return; out->role = (int)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return; out->team = (int)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

static void parse_status(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt; uint64_t v;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return; out->battery = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

static void parse_pli(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    out->kind = MESH_ATAK_PLI;
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt; uint64_t v;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return;
                out->lat_deg = (double)pb_zigzag32((uint32_t)v) * 1e-7;
                out->have_lat = true; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return;
                out->lon_deg = (double)pb_zigzag32((uint32_t)v) * 1e-7;
                out->have_lon = true; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return;
                out->altitude_hae_m = (int32_t)v; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return;
                out->speed_mps = (uint32_t)v; break;
        case 5: if (!pb_read_varint(&p, end, &v)) return;
                out->course_deg = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

static void parse_chat(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    out->kind = MESH_ATAK_CHAT;
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        const uint8_t *bp; size_t blen;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return;
                copy_str(out->chat_message, sizeof(out->chat_message), bp, blen); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return;
                copy_str(out->chat_to, sizeof(out->chat_to), bp, blen); break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return;
                copy_str(out->chat_to_callsign, sizeof(out->chat_to_callsign), bp, blen); break;
        default: if (!pb_skip_value(&p, end, wt)) return; break;
        }
    }
}

bool mesh_decode_atak(const uint8_t *buf, size_t len, mesh_atak_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    out->kind = MESH_ATAK_NONE;
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt; uint64_t v;
        if (!pb_read_tag(&p, end, &fld, &wt)) return out->kind != MESH_ATAK_NONE;
        const uint8_t *bp; size_t blen;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false;
                out->is_compressed = v != 0; break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_contact(bp, blen, out); break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_group(bp, blen, out); break;
        case 4: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_status(bp, blen, out); break;
        case 5: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_pli(bp, blen, out); break;
        case 6: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_chat(bp, blen, out); break;
        case 7: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                out->kind = MESH_ATAK_DETAIL;
                out->detail_xml = bp; out->detail_xml_len = blen; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->kind != MESH_ATAK_NONE || out->callsign[0];
}

/* ---- TRACEROUTE_APP -- meshtastic.RouteDiscovery ---- */
static void parse_packed_uint32(const uint8_t *bp, size_t blen,
                                uint32_t *out, int *out_len, int max)
{
    const uint8_t *p = bp, *end = bp + blen;
    while (p < end && *out_len < max) {
        uint64_t v;
        if (!pb_read_varint(&p, end, &v)) break;
        out[(*out_len)++] = (uint32_t)v;
    }
}

bool mesh_decode_traceroute(const uint8_t *buf, size_t len, mesh_traceroute_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        const uint8_t *bp; size_t blen;
        switch (fld) {
        case 1: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_packed_uint32(bp, blen, out->route, &out->route_len, 16); break;
        case 2: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                {
                    int i = 0;
                    const uint8_t *q = bp, *qend = bp + blen;
                    while (q < qend && i < 16) {
                        uint64_t v;
                        if (!pb_read_varint(&q, qend, &v)) break;
                        out->snr_towards[i++] = (int8_t)pb_zigzag32((uint32_t)v);
                    }
                    out->snr_towards_len = i;
                }
                break;
        case 3: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                parse_packed_uint32(bp, blen, out->route_back, &out->route_back_len, 16); break;
        case 4: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                {
                    int i = 0;
                    const uint8_t *q = bp, *qend = bp + blen;
                    while (q < qend && i < 16) {
                        uint64_t v;
                        if (!pb_read_varint(&q, qend, &v)) break;
                        out->snr_back[i++] = (int8_t)pb_zigzag32((uint32_t)v);
                    }
                    out->snr_back_len = i;
                }
                break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->route_len > 0 || out->route_back_len > 0;
}
