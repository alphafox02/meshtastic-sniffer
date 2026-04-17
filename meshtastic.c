/*
 * meshtastic-sniffer: protocol constant tables + tiny helpers.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "meshtastic.h"

#include <ctype.h>
#include <string.h>

/* Stock Meshtastic default-channel PSK (the bytes the firmware uses
 * out of the box for "LongFast"). simpleN keys are formed by replacing
 * the last byte with N; simple0 means no encryption. */
const uint8_t MESH_DEFAULT_PSK[16] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
};

/* ---- Port name lookup ---- */

struct port_name { uint32_t id; const char *name; };

static const struct port_name PORT_NAMES[] = {
    { MESH_PORT_UNKNOWN,                "UNKNOWN_APP"                 },
    { MESH_PORT_TEXT_MESSAGE,           "TEXT_MESSAGE_APP"            },
    { MESH_PORT_REMOTE_HARDWARE,        "REMOTE_HARDWARE_APP"         },
    { MESH_PORT_POSITION,               "POSITION_APP"                },
    { MESH_PORT_NODEINFO,               "NODEINFO_APP"                },
    { MESH_PORT_ROUTING,                "ROUTING_APP"                 },
    { MESH_PORT_ADMIN,                  "ADMIN_APP"                   },
    { MESH_PORT_TEXT_MESSAGE_COMPRESSED,"TEXT_MESSAGE_COMPRESSED_APP" },
    { MESH_PORT_WAYPOINT,               "WAYPOINT_APP"                },
    { MESH_PORT_AUDIO,                  "AUDIO_APP"                   },
    { MESH_PORT_DETECTION_SENSOR,       "DETECTION_SENSOR_APP"        },
    { MESH_PORT_ALERT,                  "ALERT_APP"                   },
    { MESH_PORT_KEY_VERIFICATION,       "KEY_VERIFICATION_APP"        },
    { MESH_PORT_REPLY,                  "REPLY_APP"                   },
    { MESH_PORT_IP_TUNNEL,              "IP_TUNNEL_APP"               },
    { MESH_PORT_PAXCOUNTER,             "PAXCOUNTER_APP"              },
    { MESH_PORT_STORE_FORWARD_PLUSPLUS, "STORE_FORWARD_PLUSPLUS_APP"  },
    { MESH_PORT_NODE_STATUS,            "NODE_STATUS_APP"             },
    { MESH_PORT_SERIAL,                 "SERIAL_APP"                  },
    { MESH_PORT_STORE_FORWARD,          "STORE_FORWARD_APP"           },
    { MESH_PORT_RANGE_TEST,             "RANGE_TEST_APP"              },
    { MESH_PORT_TELEMETRY,              "TELEMETRY_APP"               },
    { MESH_PORT_ZPS,                    "ZPS_APP"                     },
    { MESH_PORT_SIMULATOR,              "SIMULATOR_APP"               },
    { MESH_PORT_TRACEROUTE,             "TRACEROUTE_APP"              },
    { MESH_PORT_NEIGHBORINFO,           "NEIGHBORINFO_APP"            },
    { MESH_PORT_ATAK_PLUGIN,            "ATAK_PLUGIN"                 },
    { MESH_PORT_MAP_REPORT,             "MAP_REPORT_APP"              },
    { MESH_PORT_POWERSTRESS,            "POWERSTRESS_APP"             },
    { MESH_PORT_RETICULUM_TUNNEL,       "RETICULUM_TUNNEL_APP"        },
    { MESH_PORT_PRIVATE,                "PRIVATE_APP"                 },
    { MESH_PORT_ATAK_FORWARDER,         "ATAK_FORWARDER"              },
};
#define PORT_NAMES_COUNT (int)(sizeof(PORT_NAMES)/sizeof(PORT_NAMES[0]))

const char *mesh_port_name(uint32_t port)
{
    for (int i = 0; i < PORT_NAMES_COUNT; ++i)
        if (PORT_NAMES[i].id == port)
            return PORT_NAMES[i].name;
    return "UNKNOWN";
}

/* ---- Channel hash (XOR of all bytes of name and key, then XOR'd) ---- */

static uint8_t xor_hash_bytes(const uint8_t *p, size_t n)
{
    uint8_t h = 0;
    for (size_t i = 0; i < n; ++i)
        h ^= p[i];
    return h;
}

uint8_t mesh_channel_hash(const char *channel_name,
                          const uint8_t *psk, size_t psk_len)
{
    uint8_t hn = channel_name
        ? xor_hash_bytes((const uint8_t *)channel_name, strlen(channel_name))
        : 0;
    uint8_t hk = (psk && psk_len) ? xor_hash_bytes(psk, psk_len) : 0;
    return hn ^ hk;
}

/* ---- Preset / region lookup with tolerant name matching ---- */

static int strcasematch(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

const mesh_preset_def_t *mesh_lookup_preset(const char *name)
{
    if (!name) return NULL;
    /* accept "LongFast", "LONG_FAST", "long-fast", "longfast" */
    char buf[32]; size_t j = 0;
    for (size_t i = 0; name[i] && j + 1 < sizeof(buf); ++i) {
        char c = name[i];
        if (c == '_' || c == '-' || c == ' ') continue;
        buf[j++] = (char)tolower((unsigned char)c);
    }
    buf[j] = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        char canon[32]; size_t k = 0;
        for (size_t i = 0; MESH_PRESETS[p].name[i] && k + 1 < sizeof(canon); ++i) {
            char c = MESH_PRESETS[p].name[i];
            if (c == '_') continue;
            canon[k++] = (char)tolower((unsigned char)c);
        }
        canon[k] = 0;
        if (strcmp(buf, canon) == 0)
            return &MESH_PRESETS[p];
        /* also accept channel_name form: "longfast" matches "LongFast" */
        if (strcasematch(buf, MESH_PRESETS[p].channel_name))
            return &MESH_PRESETS[p];
    }
    return NULL;
}

const mesh_region_t *mesh_lookup_region(const char *name)
{
    if (!name) return NULL;
    /* common aliases */
    const char *aliased = name;
    if (strcasematch(name, "EU868")) aliased = "EU_868";
    else if (strcasematch(name, "EU433")) aliased = "EU_433";
    else if (strcasematch(name, "LORA24") || strcasematch(name, "LORA_2G4")) aliased = "LORA_24";

    for (int i = 0; i < MESH_REGION_COUNT; ++i)
        if (strcasematch(aliased, MESH_REGIONS[i].name))
            return &MESH_REGIONS[i];
    return NULL;
}
