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

/* ---- POSITION_APP -- meshtastic.Position ----
 *
 * Field tag and wire type discipline:
 *   1  sfixed32 latitude_i               -> wire type 5 (fixed32), signed
 *   2  sfixed32 longitude_i              -> wire type 5 (fixed32), signed
 *   3  int32    altitude (MSL)           -> wire type 0 (varint)
 *   4  fixed32  time (sender wall)       -> wire type 5 (fixed32), unsigned
 *   5  LocSource location_source         -> wire type 0 (varint)
 *   6  AltSource altitude_source         -> wire type 0 (varint)
 *   7  fixed32  timestamp (GPS fix)      -> wire type 5 (fixed32), unsigned
 *   8  int32    timestamp_millis_adjust  -> wire type 0 (varint), signed
 *   9  sint32   altitude_hae             -> wire type 0 (varint), zigzag
 *  10  sint32   altitude_geoidal_sep     -> wire type 0 (varint), zigzag
 *  11..23 uint32 fields per the proto   -> wire type 0 (varint)
 *
 * Wire-type-aware: if a tag comes in with an unexpected wire type for its
 * field number, the value is skipped rather than misparsed. This avoids
 * the prior class of bug where field 1 was read as varint even though
 * sfixed32 is wire-type 5 (always returned 0,0 in practice).
 */
bool mesh_decode_position(const uint8_t *buf, size_t len, mesh_position_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;

    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint32_t f32; uint64_t v;
        switch (fld) {
        /* sfixed32 lat/lon: 4 bytes little-endian, two's-complement signed,
         * scaled 1e-7 to degrees. */
        case 1:
            if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->lat_deg  = (double)(int32_t)f32 * 1e-7;
            out->have_lat = true; break;
        case 2:
            if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->lon_deg  = (double)(int32_t)f32 * 1e-7;
            out->have_lon = true; break;
        case 3:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->altitude_m = (int32_t)v;
            out->have_alt = true; break;
        case 4:
            if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->time = f32;
            out->have_time = true; break;
        case 5:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->location_source = (uint32_t)v; break;
        case 6:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->altitude_source = (uint32_t)v; break;
        case 7:
            if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->timestamp = f32;
            out->have_timestamp = true; break;
        case 8:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->timestamp_millis_adjust = (int32_t)v; break;
        /* sint32 fields: varint + zigzag */
        case 9:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->altitude_hae_m = pb_zigzag32((uint32_t)v);
            out->have_alt_hae = true; break;
        case 10:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->altitude_geoidal_separation_m = pb_zigzag32((uint32_t)v);
            out->have_alt_geosep = true; break;
        /* uint32 varint fields 11..23 */
        case 11:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->pdop_x100 = (uint32_t)v; break;
        case 12:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->hdop_x100 = (uint32_t)v; break;
        case 13:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->vdop_x100 = (uint32_t)v; break;
        case 14:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->gps_accuracy_mm = (uint32_t)v; break;
        case 15:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->ground_speed_mps = (uint32_t)v;
            out->have_ground_speed = true; break;
        case 16:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->ground_track_x100 = (uint32_t)v;
            out->have_ground_track = true; break;
        case 17:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->fix_quality = (uint32_t)v; break;
        case 18:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->fix_type = (uint32_t)v; break;
        case 19:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->sats_in_view = (uint32_t)v; break;
        case 20:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->sensor_id = (uint32_t)v; break;
        case 21:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->next_update_s = (uint32_t)v; break;
        case 22:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->seq_number = (uint32_t)v; break;
        case 23:
            if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return false; break; }
            out->precision_bits = (uint32_t)v; break;
        default:
            if (!pb_skip_value(&p, end, wt)) return false;
            break;
        }
    }
    return out->have_lat || out->have_lon || out->have_time || out->have_timestamp;
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

/* EnvironmentMetrics: float fields are wire-type 5 fixed32 (read as u32
 * then bit-cast); iaq, wind_direction, soil_moisture are uint32 varint
 * (wire-type 0). Field numbers and types mirror the current upstream
 * proto, including a swap that previously had wind_gust/wind_lull living
 * on the wrong field numbers. */
static void parse_env_metrics(const uint8_t *buf, size_t len, mesh_telemetry_t *out)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        uint32_t f32; uint64_t v;
        switch (fld) {
        case 1:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->temperature_c           = u32_as_float(f32); break;
        case 2:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->relative_humidity       = u32_as_float(f32); break;
        case 3:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->barometric_pressure_hpa = u32_as_float(f32); break;
        case 4:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->gas_resistance          = u32_as_float(f32); break;
        case 5:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->voltage_env             = u32_as_float(f32); break;
        case 6:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->current                 = u32_as_float(f32); break;
        /* field 7: iaq is uint32, not float. Was previously read as fixed32
         * so the reported value was garbage (e.g. an air-quality index of
         * a few hundred showed as a denormal/huge float). */
        case 7:  if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->iaq = (uint32_t)v; break;
        case 8:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->distance_mm             = u32_as_float(f32); break;
        case 9:  if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->lux                     = u32_as_float(f32); break;
        case 10: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->white_lux               = u32_as_float(f32); break;
        case 11: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->ir_lux                  = u32_as_float(f32); break;
        case 12: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->uv_lux                  = u32_as_float(f32); break;
        /* field 13: wind_direction is uint32, not float. */
        case 13: if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->wind_direction = (uint32_t)v; break;
        case 14: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->wind_speed              = u32_as_float(f32); break;
        /* fields 15..17 were previously shifted: we had wind_gust on
         * field 15 (which is actually `weight`), wind_lull on field 16
         * (which is actually wind_gust), and didn't read field 17 at all
         * (which is wind_lull). Realign with the current proto. */
        case 15: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->weight                  = u32_as_float(f32); break;
        case 16: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->wind_gust               = u32_as_float(f32); break;
        case 17: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->wind_lull               = u32_as_float(f32); break;
        /* Newer sensor fields (radiation, rainfall, soil_*) -- surface
         * the common ones so a Geiger or weather-station node shows up
         * with real data instead of getting silently dropped. */
        case 18: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->radiation_uSvh          = u32_as_float(f32); break;
        case 19: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->rainfall_1h_mm          = u32_as_float(f32); break;
        case 20: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->rainfall_24h_mm         = u32_as_float(f32); break;
        case 21: if (wt != 0 || !pb_read_varint(&p, end, &v)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->soil_moisture = (uint32_t)v; break;
        case 22: if (wt != 5 || !pb_read_fixed32(&p, end, &f32)) { if (!pb_skip_value(&p, end, wt)) return; break; }
                 out->soil_temperature_c      = u32_as_float(f32); break;
        default:
            if (!pb_skip_value(&p, end, wt)) return;
            break;
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

/* RouteDiscovery sub-message: repeated uint32 route = 1 (varint),
 * repeated int32 snr_towards = 2, repeated uint32 route_back = 3,
 * repeated int32 snr_back = 4. We surface the node-ID path; SNRs and
 * reverse path skipped for now. */
static void parse_route_discovery(const uint8_t *buf, size_t len, mesh_routing_t *out)
{
    const int route_cap = (int)(sizeof(out->route)/sizeof(out->route[0]));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return;
        if (fld == 1) {
            if (wt == 0) {
                /* Unpacked varint, one tag per element. */
                uint64_t v;
                if (!pb_read_varint(&p, end, &v)) return;
                if (out->n_route < route_cap) out->route[out->n_route++] = (uint32_t)v;
            } else if (wt == 2) {
                /* Packed varint block. */
                const uint8_t *bp; size_t blen;
                if (!pb_read_length(&p, end, &bp, &blen)) return;
                const uint8_t *q = bp, *qend = bp + blen;
                while (q < qend && out->n_route < route_cap) {
                    uint64_t v;
                    if (!pb_read_varint(&q, qend, &v)) break;
                    out->route[out->n_route++] = (uint32_t)v;
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
        case 2: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->lat_deg = (double)(int32_t)f * 1e-7; out->have_lat = true; break; }
        case 3: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->lon_deg = (double)(int32_t)f * 1e-7; out->have_lon = true; break; }
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->expire = (uint32_t)v; break;
        case 5: if (!pb_read_varint(&p, end, &v)) return false; out->locked_to = (uint32_t)v; break;
        case 6: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->name, sizeof(out->name), bp, blen); break;
        case 7: if (!pb_read_length(&p, end, &bp, &blen)) return false;
                copy_str(out->description, sizeof(out->description), bp, blen); break;
        case 8: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->icon = f; break; }
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
        case 3: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return;
                  n->last_rx_time = f; break; }
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
                  out->lat_deg = (double)(int32_t)f * 1e-7; out->have_lat = true; break; }
        case 10:{ uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return false;
                  out->lon_deg = (double)(int32_t)f * 1e-7; out->have_lon = true; break; }
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
        "Unspecified","TeamMember","TeamLead","HQ","Sniper","Medic",
        "ForwardObserver","RTO","K9"
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
        case 1: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return;
                  out->lat_deg = (double)(int32_t)f * 1e-7;
                  out->have_lat = true; break; }
        case 2: { uint32_t f; if (!pb_read_fixed32(&p, end, &f)) return;
                  out->lon_deg = (double)(int32_t)f * 1e-7;
                  out->have_lon = true; break; }
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
                        out->snr_towards[i++] = (int8_t)(int32_t)v;
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
                        out->snr_back[i++] = (int8_t)(int32_t)v;
                    }
                    out->snr_back_len = i;
                }
                break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return out->route_len > 0 || out->route_back_len > 0;
}

/* ---- REMOTE_HARDWARE_APP -- meshtastic.HardwareMessage ----
 *
 * Fields:
 *   1 type           (varint, enum)
 *   2 gpio_mask      (varint uint64)
 *   3 gpio_value     (varint uint64)
 *   4 txid           (varint uint32)
 */
bool mesh_decode_remote_hw(const uint8_t *buf, size_t len, mesh_remote_hw_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->type = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false; out->gpio_mask = v; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false; out->gpio_value = v; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->txid = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return true;
}

/* ---- DETECTION_SENSOR_APP ----
 *
 * Plain UTF-8 bytes describing the detection event ("Detection event",
 * etc). No protobuf wrapper; the on-the-wire payload IS the text. */
bool mesh_decode_detection(const uint8_t *buf, size_t len, mesh_detection_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    size_t n = len < sizeof(out->text) - 1 ? len : sizeof(out->text) - 1;
    memcpy(out->text, buf, n);
    out->text[n] = 0;
    return n > 0;
}

/* ---- STORE_FORWARD_APP -- meshtastic.StoreAndForward ----
 *
 * Wire layout:
 *   1 rr        (varint, RequestResponse enum)
 *   2 stats     (Statistics submessage)
 *   3 history   (History submessage)
 *   4 heartbeat (Heartbeat submessage)
 *   5 text      (bytes)
 *   6 empty     (bool)
 *
 * Statistics fields we surface:
 *   1 messages_total, 2 messages_history (saved), 3 messages_max,
 *   4 up_time, 5 requests
 * History fields we surface:
 *   1 history_messages, 2 window (seconds)
 *
 * Other Statistics/History fields are skipped (client-state fields the
 * observer cannot act on without joining the mesh).
 */
static bool sf_decode_stats(const uint8_t *p, const uint8_t *end, mesh_storeforward_t *out)
{
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->stats_total    = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false; out->stats_history  = (uint32_t)v; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false; out->stats_max      = (uint32_t)v; break;
        case 4: if (!pb_read_varint(&p, end, &v)) return false; out->stats_up_time_s= (uint32_t)v; break;
        case 5: if (!pb_read_varint(&p, end, &v)) return false; out->stats_requests = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return true;
}

static bool sf_decode_history(const uint8_t *p, const uint8_t *end, mesh_storeforward_t *out)
{
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->hist_count    = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false; out->hist_window_s = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return true;
}

bool mesh_decode_storeforward(const uint8_t *buf, size_t len, mesh_storeforward_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint64_t v;
        if (fld == 1) {
            if (!pb_read_varint(&p, end, &v)) return false;
            out->rr = (uint32_t)v;
        } else if (fld == 2 && wt == 2) {
            uint64_t sublen;
            if (!pb_read_varint(&p, end, &sublen)) return false;
            if ((size_t)(end - p) < sublen) return false;
            if (sf_decode_stats(p, p + sublen, out)) out->have_stats = true;
            p += sublen;
        } else if (fld == 3 && wt == 2) {
            uint64_t sublen;
            if (!pb_read_varint(&p, end, &sublen)) return false;
            if ((size_t)(end - p) < sublen) return false;
            if (sf_decode_history(p, p + sublen, out)) out->have_history = true;
            p += sublen;
        } else {
            if (!pb_skip_value(&p, end, wt)) return false;
        }
    }
    return true;
}

const char *mesh_storeforward_rr_name(uint32_t rr)
{
    switch (rr) {
    case 0:   return "UNSET";
    case 1:   return "ROUTER_ERROR";
    case 2:   return "ROUTER_HEARTBEAT";
    case 3:   return "ROUTER_PING";
    case 4:   return "ROUTER_PONG";
    case 5:   return "ROUTER_BUSY";
    case 6:   return "ROUTER_HISTORY";
    case 7:   return "ROUTER_STATS";
    case 8:   return "ROUTER_TEXT_BROADCAST";
    case 9:   return "ROUTER_TEXT_DIRECT";
    case 64:  return "CLIENT_ERROR";
    case 65:  return "CLIENT_HISTORY";
    case 66:  return "CLIENT_STATS";
    case 67:  return "CLIENT_PING";
    case 68:  return "CLIENT_PONG";
    case 69:  return "CLIENT_TEXT";
    case 106: return "CLIENT_ABORT";
    default:  return NULL;
    }
}

/* ---- PAXCOUNTER_APP -- meshtastic.Paxcount ----
 *
 * Fields:
 *   1 wifi    (varint)
 *   2 ble     (varint)
 *   3 uptime  (varint, seconds)
 */
bool mesh_decode_paxcounter(const uint8_t *buf, size_t len, mesh_paxcounter_t *out)
{
    if (!buf || !out) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        uint64_t v;
        switch (fld) {
        case 1: if (!pb_read_varint(&p, end, &v)) return false; out->wifi = (uint32_t)v; break;
        case 2: if (!pb_read_varint(&p, end, &v)) return false; out->ble = (uint32_t)v; break;
        case 3: if (!pb_read_varint(&p, end, &v)) return false; out->uptime_s = (uint32_t)v; break;
        default: if (!pb_skip_value(&p, end, wt)) return false; break;
        }
    }
    return true;
}
