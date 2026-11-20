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
    bool           pki_encrypted;      /* decrypted with a public-key (PKI) DM key */

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
    uint64_t       freq_hz;        /* RF center freq of the slot the frame arrived on; 0 = unknown */
    char           preset_name[24]; /* "LongFast" / "LongSlow" / ... or "" */

    /* Decoder slot index (0..CHANNELIZER_MAX_CHANNELS-1) -- which of the
     * many parallel demodulator slots caught this frame. Lets operators
     * map a JSON event back to the specific (frequency, BW, SF, CR) tuple
     * the decoder was tuned to, independent of the in-protocol channel
     * hash byte. -1 when the frame didn't come from a tuned LoRa slot
     * (synthetic test events, etc.). */
    int            slot_id;

    /* RF-quality telemetry from the LoRa demod. The fields below are
     * computed for every received frame; main.c stamps them onto the
     * event before publish via on_mesh_event. Defaults (zero / false)
     * mean "no useful value to report" and feed.c suppresses them. */
    bool           has_crc;          /* payload had a trailing CRC16 trailer */
    bool           payload_crc_ok;   /* CRC verified; meaningful only when has_crc */
    float          cfo_hz;           /* carrier-frequency offset estimate */

    /* Per-station capture timestamp + self-reported accuracy (ns).
     * station_t_ns is host wall-clock at receive time (ns since epoch).
     * station_t_acc_ns is this station's clock-discipline class:
     *     <= 100         GPSDO + 1PPS-locked SDR sample counter
     *     <= 10000       chrony + PPS host clock
     *     <= 1000000     chrony + NTP host clock
     *     1000000+       unsynchronized / unknown
     * The fusion-side mlat solver uses station_t_acc_ns to weight
     * observations; a poorly-synchronized station effectively votes
     * less than a GPSDO-locked one. 0 means "not populated". */
    uint64_t       station_t_ns;
    uint32_t       station_t_acc_ns;

    /* TDOA metadata: SDR-rate absolute sample index at the moment of
     * preamble lock for this frame, plus the sample rate so fusion can
     * convert sample deltas into seconds. preamble_lock_sample_idx is
     * monotonically increasing per station; cross-station alignment
     * requires GPSDO/PPS clocks (see station_t_acc_ns). Both 0 when
     * the source isn't a tuned LoRa decoder. */
    uint64_t       preamble_lock_sample_idx;
    uint64_t       sample_rate_sps;
    /* Fractional-sample timing offset of the preamble peak, in
     * SDR-sample units. Combines with preamble_lock_sample_idx:
     *     toa_sample = preamble_lock_sample_idx + preamble_lock_sample_frac
     * Read-only metadata; the decoder does not feed this back into
     * STO/CFO/SFO. 0 when no fractional estimate was available. */
    float          preamble_lock_sample_frac;
    /* CLOCK_REALTIME at the moment preamble lock was detected.
     * Strictly earlier than station_t_ns (which the dedup ring
     * stamps when the first replica is buffered, after the frame
     * has fully demodulated). Fusion uses this as a software-lock
     * timing source when present; it is not a sample-derived
     * GPSDO-grade TOA -- PFB / scheduling / buffering latency are
     * still baked in. 0 when not populated. */
    uint64_t       preamble_lock_t_ns;

    /* Inner Data envelope (when decrypted == true) */
    uint32_t       portnum;
    const uint8_t *payload;
    size_t         payload_len;
    uint32_t       request_id;         /* protobuf field 6 (or 0) */
    uint32_t       reply_id;           /* protobuf field 7 (or 0) */
    bool           want_response;      /* protobuf field 3 */

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

/* Optional public-key (PKI) decrypt hook, tried for unicast frames whose
 * channel-hash byte is 0 before the channel keys. Returns the plaintext
 * length, or -1 if it can't decrypt (not ours / unknown sender key / bad
 * tag). NULL (the default) disables it; the TX path installs pki.c's. */
typedef int (*mesh_pki_decrypt_fn)(uint32_t from, uint32_t to, uint32_t packet_id,
                                   const uint8_t *body, size_t n,
                                   uint8_t *out, size_t cap);
void mesh_packet_set_pki_decrypt(mesh_pki_decrypt_fn fn);

#endif
