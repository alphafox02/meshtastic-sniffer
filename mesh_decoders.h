/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: per-port protobuf decoders.
 *
 * Each function takes the raw payload bytes from a Data envelope and
 * produces a typed struct. Returns true if at least one field parsed
 * cleanly (best-effort: malformed extras are skipped, not fatal).
 *
 */

#ifndef MESH_DECODERS_H
#define MESH_DECODERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- POSITION_APP (port 3) ---- */
typedef struct mesh_position {
    bool     have_lat, have_lon, have_alt;
    double   lat_deg, lon_deg;
    int32_t  altitude_m;
    uint32_t time_unix;
    uint32_t sats_in_view;
    uint32_t pdop_x100;       /* PDOP * 100 */
    uint32_t ground_speed_mps;
    uint32_t ground_track;    /* degrees */
    uint32_t precision_bits;
    uint32_t location_source; /* enum LocationSource */
} mesh_position_t;
bool mesh_decode_position(const uint8_t *buf, size_t len, mesh_position_t *out);

/* ---- NODEINFO_APP (port 4, message User) ---- */
typedef struct mesh_user {
    char     id[24];          /* "!a4c1b9d2" style */
    char     long_name[64];
    char     short_name[8];
    uint8_t  macaddr[6];
    bool     have_macaddr;
    uint32_t hw_model;        /* enum HardwareModel */
    bool     is_licensed;
    uint32_t role;            /* enum Role */
    uint8_t  public_key[32];
    bool     have_public_key;
} mesh_user_t;
bool mesh_decode_user(const uint8_t *buf, size_t len, mesh_user_t *out);

/* ---- TELEMETRY_APP (port 67) -- the union of common variants ---- */
typedef struct mesh_telemetry {
    uint32_t time_unix;

    bool     have_device;
    uint32_t battery_level;       /* 0..100, 101 = USB */
    float    voltage;             /* Volts */
    float    channel_utilization; /* % */
    float    air_util_tx;         /* % */
    uint32_t uptime_seconds;

    bool     have_environment;
    float    temperature_c;
    float    relative_humidity;
    float    barometric_pressure_hpa;
    float    gas_resistance;
    float    voltage_env;
    float    current;
    float    iaq;
    float    distance_mm;
    float    lux, white_lux, ir_lumens, uv_lux;
    float    wind_direction;
    float    wind_speed;
    float    wind_gust;
    float    wind_lull;

    bool     have_power;
    float    ch1_voltage, ch1_current;
    float    ch2_voltage, ch2_current;
    float    ch3_voltage, ch3_current;
} mesh_telemetry_t;
bool mesh_decode_telemetry(const uint8_t *buf, size_t len, mesh_telemetry_t *out);

/* ---- ROUTING_APP (port 5) ----
 *
 * meshtastic.Routing { oneof variant {
 *     RouteDiscovery route_request = 1;
 *     RouteDiscovery route_reply   = 2;
 *     Error          error_reason  = 3;
 * }}
 * RouteDiscovery contains repeated fixed32 route node IDs, optionally
 * with per-hop SNRs in dB*4. We surface variant + the node-ID path so
 * mesh-routing visibility is possible from header-only intel. */
typedef enum {
    MESH_ROUTING_NONE = 0,
    MESH_ROUTING_REQUEST,
    MESH_ROUTING_REPLY,
    MESH_ROUTING_ERROR,
} mesh_routing_kind_t;

typedef struct mesh_routing {
    mesh_routing_kind_t kind;
    /* MESH_ROUTING_ERROR */
    uint32_t error_reason;
    /* MESH_ROUTING_REQUEST / MESH_ROUTING_REPLY */
    int      n_route;
    uint32_t route[16];          /* forward path: source ... dest */
    /* legacy: kept for source compat with feed.c that read these fields. */
    bool     have_error;
} mesh_routing_t;
bool mesh_decode_routing(const uint8_t *buf, size_t len, mesh_routing_t *out);

/* ---- ATAK_PLUGIN (port 72) -- meshtastic.atak.TAKPacket ---- */
typedef enum {
    MESH_ATAK_NONE = 0,
    MESH_ATAK_PLI,
    MESH_ATAK_CHAT,
    MESH_ATAK_DETAIL,   /* full uncompressed CoT XML */
} mesh_atak_kind_t;

typedef struct mesh_atak {
    bool   is_compressed;
    char   callsign[32];
    char   device_callsign[32];
    int    team;        /* enum Team: White/Yellow/Orange/Magenta/Red/Maroon/Purple/DarkBlue/Blue/Cyan/Teal/Green/DarkGreen/Brown */
    int    role;        /* enum Role: TeamMember/TeamLead/HQ/Sniper/Medic/ForwardObserver/RTO/K9 */
    uint32_t battery;

    mesh_atak_kind_t kind;

    /* PLI variant */
    bool     have_lat, have_lon;
    double   lat_deg, lon_deg;
    int32_t  altitude_hae_m;
    uint32_t speed_mps;
    uint32_t course_deg;

    /* CHAT variant */
    char     chat_message[200];
    char     chat_to[64];
    char     chat_to_callsign[32];

    /* DETAIL variant -- raw CoT XML bytes for republish */
    const uint8_t *detail_xml;
    size_t         detail_xml_len;
} mesh_atak_t;
bool mesh_decode_atak(const uint8_t *buf, size_t len, mesh_atak_t *out);
const char *mesh_atak_team_name(int team);
const char *mesh_atak_role_name(int role);

/* ---- WAYPOINT_APP (port 8) ---- */
typedef struct mesh_waypoint {
    uint32_t id;
    bool     have_lat, have_lon;
    double   lat_deg, lon_deg;
    uint32_t expire;            /* unix time */
    uint32_t locked_to;         /* node id, 0 = unlocked */
    char     name[32];
    char     description[80];
    uint32_t icon;              /* unicode codepoint */
} mesh_waypoint_t;
bool mesh_decode_waypoint(const uint8_t *buf, size_t len, mesh_waypoint_t *out);

/* ---- NEIGHBORINFO_APP (port 71) ---- */
typedef struct mesh_neighbor {
    uint32_t node_id;           /* the *neighbour* of the sender */
    float    snr_db;            /* SNR in dB (firmware sends SNR*4 as int8) */
    uint32_t last_rx_time;
    uint32_t node_broadcast_interval_secs;
} mesh_neighbor_t;

typedef struct mesh_neighborinfo {
    uint32_t        node_id;
    uint32_t        last_sent_by_id;
    uint32_t        node_broadcast_interval_secs;
    int             n_neighbors;
    mesh_neighbor_t neighbors[16];
} mesh_neighborinfo_t;
bool mesh_decode_neighborinfo(const uint8_t *buf, size_t len, mesh_neighborinfo_t *out);

/* ---- KEY_VERIFICATION_APP (port 12) ----
 *
 * KeyVerification message: { nonce uint64, hash1 bytes, hash2 bytes,
 * remote_node_id uint32 }. We surface only the non-secret metadata
 * (nonce, remote_node_id, hash sizes) so observers can see that two
 * nodes are exchanging key-verification messages without leaking the
 * hashes themselves to the JSON feed. */
typedef struct mesh_keyverif {
    uint64_t nonce;
    uint32_t remote_node_id;
    int      hash1_len;
    int      hash2_len;
} mesh_keyverif_t;
bool mesh_decode_keyverif(const uint8_t *buf, size_t len, mesh_keyverif_t *out);

/* ---- MAP_REPORT_APP (port 73) ---- */
typedef struct mesh_mapreport {
    char     long_name[64];
    char     short_name[8];
    uint32_t role;
    uint32_t hw_model;
    char     firmware_version[24];
    uint32_t region;
    uint32_t modem_preset;
    uint32_t has_default_channel;
    bool     have_lat, have_lon;
    double   lat_deg, lon_deg;
    int32_t  altitude_m;
    uint32_t position_precision;
    uint32_t num_online_local_nodes;
} mesh_mapreport_t;
bool mesh_decode_mapreport(const uint8_t *buf, size_t len, mesh_mapreport_t *out);

/* ---- ADMIN_APP (port 6) ----
 *
 * AdminMessage payload_variant oneof; we surface only the field
 * number that was set so observers can tell what kind of admin RPC
 * was issued (set_owner / get_config / etc) without trying to decode
 * every variant. */
typedef struct mesh_admin {
    uint32_t variant_field;     /* protobuf field number of the oneof leg present */
    bool     has_session_passkey;
} mesh_admin_t;
bool mesh_decode_admin(const uint8_t *buf, size_t len, mesh_admin_t *out);

/* ---- TRACEROUTE_APP (port 70) ---- */
typedef struct mesh_traceroute {
    int      route_len;
    uint32_t route[16];
    int      snr_towards_len;
    int8_t   snr_towards[16];   /* SNR * 4 in firmware; we surface raw */
    int      route_back_len;
    uint32_t route_back[16];
    int      snr_back_len;
    int8_t   snr_back[16];
} mesh_traceroute_t;
bool mesh_decode_traceroute(const uint8_t *buf, size_t len, mesh_traceroute_t *out);

#endif
