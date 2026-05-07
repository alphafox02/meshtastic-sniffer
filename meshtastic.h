/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: protocol constants
 * (region bands, modem presets, port numbers, default channel grids)
 *
 */

#ifndef MESHTASTIC_H
#define MESHTASTIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Radio header (16 bytes, little-endian on the wire) ---- */

#define MESH_HEADER_BYTES         16
#define MESH_BROADCAST_NODE       0xFFFFFFFFu

#define MESH_FLAG_HOP_LIMIT_MASK  0x07
#define MESH_FLAG_WANT_ACK_MASK   0x08
#define MESH_FLAG_VIA_MQTT_MASK   0x10
#define MESH_FLAG_HOP_START_MASK  0xE0
#define MESH_FLAG_HOP_START_SHIFT 5

typedef struct mesh_header {
    uint32_t to;          /* 0xFFFFFFFF = broadcast */
    uint32_t from;        /* sender node id */
    uint32_t packet_id;   /* per-sender monotonic id (used in AES nonce) */
    uint8_t  flags;       /* hopLimit(3) | wantAck(1) | viaMqtt(1) | hopStart(3) */
    uint8_t  channel;     /* low byte of (xorHash(name) ^ xorHash(psk)) */
    uint8_t  next_hop;    /* upper byte of last-relay node id (DV-routing hint) */
    uint8_t  relay_node;  /* upper byte of relayer node id (DV-routing hint) */
} mesh_header_t;

/* ---- Modem presets ---- */

typedef enum {
    MESH_PRESET_SHORT_TURBO = 0,
    MESH_PRESET_SHORT_FAST,
    MESH_PRESET_SHORT_SLOW,
    MESH_PRESET_MEDIUM_FAST,
    MESH_PRESET_MEDIUM_SLOW,
    MESH_PRESET_LONG_FAST,        /* default channel "LongFast" -- by far the most common */
    MESH_PRESET_LONG_MODERATE,
    MESH_PRESET_LONG_SLOW,
    MESH_PRESET_LONG_TURBO,
    MESH_PRESET_COUNT
} mesh_preset_t;

typedef struct mesh_preset_def {
    const char    *name;          /* "LONG_FAST" */
    const char    *channel_name;  /* "LongFast"  -- used for channel-hash with PSK */
    int            spread_factor; /* 7..12 */
    int            coding_rate;   /* 5 = 4/5, 6 = 4/6, 7 = 4/7, 8 = 4/8 */
    int            bw_hz_narrow;  /* sub-GHz: 125 / 250 / 500 kHz */
    int            bw_hz_wide;    /* 2.4 GHz LORA_24 region: 406 / 812 / 1625 kHz */
    int            preamble_sub;  /* preamble symbols on sub-GHz */
    int            preamble_24;   /* preamble symbols at 2.4 GHz */
} mesh_preset_def_t;

/* The canonical 9-preset table. Sub-GHz BW / 2.4 GHz BW pulled from
 * meshtastic firmware RadioInterface.cpp; preamble values per
 * sdrangel meshtasticdemodgui auto-tune defaults (16 sub-GHz, 12 @ 2.4 GHz). */
static const mesh_preset_def_t MESH_PRESETS[MESH_PRESET_COUNT] = {
    /* name             channel        SF  CR   bw_sub   bw_24    pre_sub pre_24 */
    { "SHORT_TURBO",    "ShortTurbo",   7,  5,   500000,  1625000, 16, 12 },
    { "SHORT_FAST",     "ShortFast",    7,  5,   250000,   812000, 16, 12 },
    { "SHORT_SLOW",     "ShortSlow",    8,  5,   250000,   812000, 16, 12 },
    { "MEDIUM_FAST",    "MediumFast",   9,  5,   250000,   812000, 16, 12 },
    { "MEDIUM_SLOW",    "MediumSlow",  10,  5,   250000,   812000, 16, 12 },
    { "LONG_FAST",      "LongFast",    11,  5,   250000,   812000, 16, 12 },
    { "LONG_MODERATE",  "LongMod",     11,  8,   125000,   406000, 16, 12 },
    { "LONG_SLOW",      "LongSlow",    12,  8,   125000,   406000, 16, 12 },
    { "LONG_TURBO",     "LongTurbo",   11,  8,   500000,  1625000, 16, 12 },
};

/* ---- Region bands (lower/upper edges in MHz, freq slots derived per BW) ---- */

typedef struct mesh_region {
    const char *name;
    double      f_lo_mhz;
    double      f_hi_mhz;
    bool        wide_lora;        /* true for 2.4 GHz (LORA_24): use bw_24 from preset */
} mesh_region_t;

static const mesh_region_t MESH_REGIONS[] = {
    { "US",      902.0,    928.0,   false },
    { "EU_433",  433.0,    434.0,   false },
    { "EU_868",  869.4,    869.65,  false },
    { "CN",      470.0,    510.0,   false },
    { "JP",      920.5,    923.5,   false },
    { "ANZ",     915.0,    928.0,   false },
    { "ANZ_433", 433.05,   434.79,  false },
    { "RU",      868.7,    869.2,   false },
    { "KR",      920.0,    923.0,   false },
    { "TW",      920.0,    925.0,   false },
    { "IN",      865.0,    867.0,   false },
    { "NZ_865",  864.0,    868.0,   false },
    { "TH",      920.0,    925.0,   false },
    { "UA_433",  433.0,    434.7,   false },
    { "UA_868",  868.0,    868.6,   false },
    { "MY_433",  433.0,    435.0,   false },
    { "MY_919",  919.0,    924.0,   false },
    { "SG_923",  917.0,    925.0,   false },
    { "PH_433",  433.0,    434.7,   false },
    { "PH_868",  868.0,    869.4,   false },
    { "PH_915",  915.0,    918.0,   false },
    { "KZ_433",  433.075,  434.775, false },
    { "KZ_863",  863.0,    868.0,   false },
    { "NP_865",  865.0,    868.0,   false },
    { "BR_902",  902.0,    907.5,   false },
    { "LORA_24", 2400.0,   2483.5,  true  },
};
#define MESH_REGION_COUNT (int)(sizeof(MESH_REGIONS)/sizeof(MESH_REGIONS[0]))

/* Number of channel slots for (region, preset BW) -- mirrors firmware:
 * slots = floor((f_hi - f_lo) / bw). Stock LongFast on US has 104 slots;
 * EU_868 LongFast at 250 kHz has 1; users pick a slot in [0, slots). */
static inline int mesh_channel_count(const mesh_region_t *r, int bw_hz)
{
    if (!r || bw_hz <= 0) return 0;
    double span = (r->f_hi_mhz - r->f_lo_mhz) * 1.0e6;
    int n = (int)(span / (double)bw_hz);
    return n > 0 ? n : 0;
}

/* Channel-slot frequency (Hz) for a (region, BW, slot index).
 * f_n = f_lo + bw/2 + n*bw. Returns 0 if slot is out of range. */
static inline uint64_t mesh_channel_freq_hz(const mesh_region_t *r,
                                            int bw_hz,
                                            int channel_index)
{
    if (!r || bw_hz <= 0 || channel_index < 0)
        return 0;
    if (channel_index >= mesh_channel_count(r, bw_hz))
        return 0;
    double bw_mhz = bw_hz / 1.0e6;
    double f_mhz = r->f_lo_mhz + bw_mhz * 0.5 + bw_mhz * (double)channel_index;
    return (uint64_t)(f_mhz * 1.0e6 + 0.5);
}

/* ---- Application port numbers (PortNum enum from portnums.proto) ---- */

typedef enum {
    MESH_PORT_UNKNOWN                  = 0,
    MESH_PORT_TEXT_MESSAGE             = 1,
    MESH_PORT_REMOTE_HARDWARE          = 2,
    MESH_PORT_POSITION                 = 3,
    MESH_PORT_NODEINFO                 = 4,
    MESH_PORT_ROUTING                  = 5,
    MESH_PORT_ADMIN                    = 6,
    MESH_PORT_TEXT_MESSAGE_COMPRESSED  = 7,
    MESH_PORT_WAYPOINT                 = 8,
    MESH_PORT_AUDIO                    = 9,
    MESH_PORT_DETECTION_SENSOR         = 10,
    MESH_PORT_ALERT                    = 11,
    MESH_PORT_KEY_VERIFICATION         = 12,
    MESH_PORT_REPLY                    = 32,
    MESH_PORT_IP_TUNNEL                = 33,
    MESH_PORT_PAXCOUNTER               = 34,
    MESH_PORT_STORE_FORWARD_PLUSPLUS   = 35,
    MESH_PORT_NODE_STATUS              = 36,
    MESH_PORT_SERIAL                   = 64,
    MESH_PORT_STORE_FORWARD            = 65,
    MESH_PORT_RANGE_TEST               = 66,
    MESH_PORT_TELEMETRY                = 67,
    MESH_PORT_ZPS                      = 68,
    MESH_PORT_SIMULATOR                = 69,
    MESH_PORT_TRACEROUTE               = 70,
    MESH_PORT_NEIGHBORINFO             = 71,
    MESH_PORT_ATAK_PLUGIN              = 72,
    MESH_PORT_MAP_REPORT               = 73,
    MESH_PORT_POWERSTRESS              = 74,
    MESH_PORT_RETICULUM_TUNNEL         = 76,
    MESH_PORT_PRIVATE                  = 256,
    MESH_PORT_ATAK_FORWARDER           = 257,
} mesh_port_t;

const char *mesh_port_name(uint32_t port);     /* port name string ("TELEMETRY_APP" etc) */

/* ---- Default Meshtastic PSK ---------------------------------------------
 *
 * The "default" key (channel name "LongFast" out of the box) is a fixed
 * 16-byte PSK published in the Meshtastic firmware
 * (src/mesh/Channels.cpp -- "AQ==" base64 byte expanded by the simple-key
 * scheme). simpleN keys are formed by replacing the last byte. */
extern const uint8_t MESH_DEFAULT_PSK[16];

/* ---- Channel-hash helper ------------------------------------------------
 *
 * Per Meshtastic spec, header.channel = xorHash(channel_name) ^ xorHash(psk).
 * xorHash() is just XOR of all bytes -> single uint8. */
uint8_t mesh_channel_hash(const char *channel_name,
                          const uint8_t *psk, size_t psk_len);

/* ---- Pretty preset/region lookup ---------------------------------------- */

const mesh_preset_def_t *mesh_lookup_preset(const char *name);   /* case-insensitive, accepts "LongFast"/"LONG_FAST"/etc */
const mesh_region_t      *mesh_lookup_region(const char *name);  /* "US", "EU_868", aliases handled */

#endif /* MESHTASTIC_H */
