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

/* ---- POSITION_APP (port 3) ---- meshtastic.Position
 *
 * Field numbers, wire types, and units mirror the current upstream proto
 * (meshtastic/protobufs mesh.proto, "message Position"). lat_i/lon_i are
 * sfixed32 -- 4 raw little-endian bytes per side, two's-complement
 * signed -- not varint+zigzag; altitude_hae and altitude_geoidal_separation
 * are sint32 (varint+zigzag, signed-magnitude). Everything else is plain
 * varint (uint32 or int32) or fixed32 per the proto.
 *
 * have_* flags are per-field so a consumer can tell "0 explicit" from
 * "0 because the sender didn't include this field." Required for the JSON
 * feed not to lie when a node only sends partial Position. */
typedef struct mesh_position {
    bool     have_lat, have_lon;
    bool     have_alt, have_alt_hae, have_alt_geosep;
    bool     have_time, have_timestamp;
    bool     have_ground_speed, have_ground_track;

    double   lat_deg, lon_deg;             /* sfixed32 fields 1,2 * 1e-7 -> degrees */
    int32_t  altitude_m;                   /* int32  field 3:  MSL altitude (meters) */
    uint32_t time;                         /* fixed32 field 4: sender wall-clock when message was sent (epoch s) */
    uint32_t location_source;              /* enum    field 5:  LocSource */
    uint32_t altitude_source;              /* enum    field 6:  AltSource */
    uint32_t timestamp;                    /* fixed32 field 7:  actual GPS-fix timestamp (epoch s) */
    int32_t  timestamp_millis_adjust;      /* int32   field 8:  ms adjustment relative to `timestamp` */
    int32_t  altitude_hae_m;               /* sint32  field 9:  HAE altitude (meters) */
    int32_t  altitude_geoidal_separation_m;/* sint32  field 10: geoid separation (meters) */
    uint32_t pdop_x100;                    /* uint32  field 11: PDOP * 100 */
    uint32_t hdop_x100;                    /* uint32  field 12: HDOP * 100 */
    uint32_t vdop_x100;                    /* uint32  field 13: VDOP * 100 */
    uint32_t gps_accuracy_mm;              /* uint32  field 14: hardware constant (mm) */
    uint32_t ground_speed_mps;             /* uint32  field 15: m/s */
    uint32_t ground_track_x100;            /* uint32  field 16: 1/100 degrees */
    uint32_t fix_quality;                  /* uint32  field 17: NMEA fix quality */
    uint32_t fix_type;                     /* uint32  field 18: NMEA fix type (2D/3D) */
    uint32_t sats_in_view;                 /* uint32  field 19 */
    uint32_t sensor_id;                    /* uint32  field 20 */
    uint32_t next_update_s;                /* uint32  field 21: expected seconds until next update */
    uint32_t seq_number;                   /* uint32  field 22 */
    uint32_t precision_bits;               /* uint32  field 23 */
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
    uint32_t iaq;                         /* field 7: uint32 per proto, NOT float */
    float    distance_mm;
    float    lux, white_lux, ir_lux, uv_lux;
    uint32_t wind_direction;              /* field 13: uint32 per proto, NOT float */
    float    wind_speed;
    float    weight;                      /* field 15 */
    float    wind_gust;                   /* field 16 (was wired to field 15) */
    float    wind_lull;                   /* field 17 (was wired to field 16) */
    float    radiation_uSvh;              /* field 18 */
    float    rainfall_1h_mm;              /* field 19 */
    float    rainfall_24h_mm;             /* field 20 */
    uint32_t soil_moisture;               /* field 21 */
    float    soil_temperature_c;          /* field 22 */

    bool     have_power;
    float    ch1_voltage, ch1_current;
    float    ch2_voltage, ch2_current;
    float    ch3_voltage, ch3_current;
    float    ch4_voltage, ch4_current;
    float    ch5_voltage, ch5_current;
    float    ch6_voltage, ch6_current;
    float    ch7_voltage, ch7_current;
    float    ch8_voltage, ch8_current;

    bool     have_local_stats;
    uint32_t local_uptime_s;
    float    local_channel_utilization;
    float    local_air_util_tx;
    uint32_t local_num_packets_tx;
    uint32_t local_num_packets_rx;
    uint32_t local_num_packets_rx_bad;
    uint32_t local_num_online_nodes;
    uint32_t local_num_total_nodes;
    uint32_t local_num_rx_dupe;
    uint32_t local_num_tx_relay;
    uint32_t local_num_tx_relay_canceled;
    uint32_t local_heap_total_bytes;
    uint32_t local_heap_free_bytes;
    uint32_t local_num_tx_dropped;
    int32_t  local_noise_floor_dbm;
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

/* ---- REMOTE_HARDWARE_APP (port 2) ----
 *
 * HardwareMessage: { type enum, gpio_mask uint64, gpio_value uint64,
 * txid uint32 }. Surfaced fields let an observer see a remote-GPIO
 * RPC happening (read/write/notify) without making policy on it. */
typedef struct mesh_remote_hw {
    uint32_t type;       /* HardwareMessage.Type enum */
    uint64_t gpio_mask;
    uint64_t gpio_value;
    uint32_t txid;
} mesh_remote_hw_t;
bool mesh_decode_remote_hw(const uint8_t *buf, size_t len, mesh_remote_hw_t *out);

/* ---- DETECTION_SENSOR_APP (port 10) ----
 *
 * DetectionSensor's payload is a short text string ("Detection event",
 * etc.) sent broadcast when a sensor-mode device sees its trigger.
 * Surface as plain text. */
typedef struct mesh_detection {
    char text[128];
} mesh_detection_t;
bool mesh_decode_detection(const uint8_t *buf, size_t len, mesh_detection_t *out);

/* ---- STORE_FORWARD_APP (port 65) ----
 *
 * StoreAndForward { rr enum, oneof variant {
 *     Statistics stats; History history; Heartbeat heartbeat;
 *     bytes text; bool empty;
 * }}.
 *
 * We surface the rr (request/response) field plus, when the variant
 * is Statistics or History, the headline counters. Lets observers
 * see store-forward routers heartbeat and clients pull history
 * without having to attach a Meshtastic client. */
typedef struct mesh_storeforward {
    uint32_t rr;                /* RequestResponse enum value */
    bool     have_stats;
    uint32_t stats_total;       /* messages_total */
    uint32_t stats_history;     /* messages_history (stored) */
    uint32_t stats_max;         /* messages_max (capacity) */
    uint32_t stats_up_time_s;
    uint32_t stats_requests;
    bool     have_history;
    uint32_t hist_count;        /* history_messages */
    uint32_t hist_window_s;     /* window in seconds covered by the request */
} mesh_storeforward_t;
bool mesh_decode_storeforward(const uint8_t *buf, size_t len, mesh_storeforward_t *out);
const char *mesh_storeforward_rr_name(uint32_t rr);

/* ---- PAXCOUNTER_APP (port 9) ----
 *
 * Paxcount: { wifi uint32, ble uint32, uptime uint32 }. Crowd-density
 * counter -- WiFi + BLE devices the sensor has seen in its window. */
typedef struct mesh_paxcounter {
    uint32_t wifi;
    uint32_t ble;
    uint32_t uptime_s;
} mesh_paxcounter_t;
bool mesh_decode_paxcounter(const uint8_t *buf, size_t len, mesh_paxcounter_t *out);

#endif
