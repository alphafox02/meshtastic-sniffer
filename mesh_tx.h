/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: build Meshtastic packets and their HackRF IQ in C.
 *
 * The C port of tools/meshtastic_tx.py (frame, channel AES-CTR or
 * public-key encryption, firmware slot hashing, int8 IQ for the HackRF),
 * on top of lora_tx.c. tests/tx holds both byte-for-byte equal. It lets
 * the sniffer transmit without python/gr-lora_sdr, which Android needs.
 */

#ifndef MESH_TX_H
#define MESH_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    MESH_TX_TEXT = 0,
    MESH_TX_POSITION,
    MESH_TX_NODEINFO,
    MESH_TX_TELEMETRY,
    MESH_TX_TRACEROUTE,
    MESH_TX_NKINDS
};

/* "text", "position", ... ; NULL for an out-of-range kind */
const char *mesh_tx_kind_name(int kind);

typedef struct {
    const char *region;          /* "EU_868", aliases ok */
    const char *preset;          /* "MEDIUM_FAST" / "MediumFast" ... */
    const char *channel;         /* NULL or "": the preset's channel name */
    const char *psk;             /* as in the app: base64, "none", "default" */
    int         slot;            /* -1: firmware hash of the channel name */
    uint32_t    from, to;        /* to = 0xFFFFFFFF: broadcast */
    int         hop_limit;       /* 0..7 */
    bool        want_ack;
    int         kind;            /* MESH_TX_* */
    const char *text;            /* MESH_TX_TEXT */
    uint32_t    reply_id;        /* MESH_TX_TEXT, 0 = none */
    const char *long_name;       /* NULL: "Meshtastic xxxx"; set: NodeInfo announced first */
    const char *short_name;
    bool        announce_dest;   /* NodeInfo to the destination first (for PKI) */
    bool        has_identity;    /* our X25519 key: NodeInfo carries the public key */
    uint8_t     our_priv[32];
    bool        has_dest_key;    /* PKI-encrypt the main packet (if its port allows) */
    uint8_t     dest_pub[32];
    double      ppm;             /* HackRF clock correction */
    uint32_t    rate;            /* sample rate, 0 = 2000000 */
    double      if_offset;       /* Hz off the LO to dodge the DC spur, 0 = 500 kHz */
    bool        frames_only;     /* skip modulation (tests) */
    uint32_t    fixed_ids[2];    /* tests: packet ids (0 = random), in send order */
    uint32_t    fixed_extra_nonce; /* tests: PKI extra nonce (0 = random) */
} mesh_tx_req_t;

typedef struct {
    char     label[16];          /* "nodeinfo", or the kind name */
    uint32_t id;
    uint64_t freq_hz;            /* channel centre */
    uint64_t lo_hz;              /* HackRF LO (freq - if_offset, ppm-corrected) */
    uint32_t rate;
    uint32_t airtime_ms;
    bool     pki;
    uint8_t  frame[256];
    size_t   frame_len;
    int8_t  *iq;                 /* interleaved int8 I/Q for the HackRF; NULL if frames_only */
    size_t   iq_bytes;
} mesh_tx_packet_t;

/* Build the packet(s) for one send: an optional NodeInfo, then the main
 * packet. Returns the count (1 or 2), or -1 with a message in err. */
int  mesh_tx_build(const mesh_tx_req_t *r, mesh_tx_packet_t *out, int max,
                   char *err, size_t errlen);
void mesh_tx_free(mesh_tx_packet_t *p, int n);

/* firmware RadioInterface: djb2 of the channel name */
uint32_t mesh_tx_djb2(const char *s);

#endif /* MESH_TX_H */
