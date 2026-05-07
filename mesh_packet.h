/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: packet decoder.
 *
 * Takes raw bytes from the LoRa demod (16-byte radio header + N
 * encrypted payload bytes), routes by channel hash to the keyset,
 * AES-CTR decrypts, parses the protobuf Data envelope, and emits a
 * structured event to a callback.
 *
 */

#ifndef MESH_PACKET_H
#define MESH_PACKET_H

#include "keyset.h"
#include "meshtastic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct mesh_event {
    /* Radio-header fields */
    mesh_header_t  header;
    int            hop_limit;
    int            hop_start;
    bool           want_ack;
    bool           via_mqtt;

    /* Decryption metadata */
    bool           decrypted;
    char           channel_name[32];   /* matched key entry; "" if none matched */

    /* Reception quality (filled in by the LoRa demod via lora_frame_meta_t,
     * 0/0 when frame originates from a non-LoRa source like the selftest). */
    float          rssi_db;
    float          snr_db;

    /* Radio-layer parameters of the channel this frame arrived on. 0 when
     * the source isn't a tuned LoRa decoder. preset_name is "" when (sf,
     * cr, bw_hz) doesn't match any canonical Meshtastic preset. */
    int            sf;
    int            cr;             /* 5..8 = 4/5..4/8 */
    int            bw_hz;
    char           preset_name[24]; /* "LongFast" / "LongSlow" / ... or "" */

    /* Inner Data envelope (when decrypted == true) */
    uint32_t       portnum;
    const uint8_t *payload;
    size_t         payload_len;
    uint32_t       request_id;         /* protobuf field 6 (or 0) */
    uint32_t       reply_id;           /* protobuf field 7 (or 0) */
    bool           want_response;      /* protobuf field 4 */

    /* Optional: extracted typed fields per port. */
    /* TEXT_MESSAGE_APP: payload is UTF-8 text directly. */
    /* POSITION_APP / NODEINFO_APP / TELEMETRY_APP: cooked into the
     * structs below by mesh_decoders.c (TODO). */
} mesh_event_t;

typedef void (*mesh_event_cb_t)(const mesh_event_t *ev, void *user);

/* One-shot decode of a complete LoRa-frame payload.
 * `frame` must include the 16-byte radio header followed by the
 * encrypted (or plaintext) inner Data bytes.
 *
 * Returns 0 if a packet was emitted (regardless of decryption success;
 * the callback receives the header even if no key matched), -1 if the
 * frame is malformed (too short). */
int mesh_packet_decode(const uint8_t *frame, size_t frame_len,
                       const keyset_t *keys,
                       mesh_event_cb_t cb, void *user);

/* Same, with explicit RSSI/SNR metadata to thread through to the
 * mesh_event_t. mesh_packet_decode() is just a wrapper that calls
 * this with rssi=snr=0. */
int mesh_packet_decode_with_meta(const uint8_t *frame, size_t frame_len,
                                 float rssi_db, float snr_db,
                                 const keyset_t *keys,
                                 mesh_event_cb_t cb, void *user);

/* Same as _with_meta, but also threads the radio-layer parameters
 * (sf/cr/bw_hz) so the JSON feed and CoT remarks can identify which
 * Meshtastic preset the frame arrived on. Pass 0 for any unknown value. */
int mesh_packet_decode_with_radio(const uint8_t *frame, size_t frame_len,
                                  float rssi_db, float snr_db,
                                  int sf, int cr, int bw_hz,
                                  const keyset_t *keys,
                                  mesh_event_cb_t cb, void *user);

#endif
