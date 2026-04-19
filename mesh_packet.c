/*
 * meshtastic-sniffer: packet decoder.
 *
 * Wire format of a Meshtastic LoRa frame (after CSS demod and CRC pass):
 *
 *   bytes  0..3:   to       (uint32 LE)
 *   bytes  4..7:   from     (uint32 LE)
 *   bytes  8..11:  packet_id (uint32 LE)   -- low 32 bits of nonce.packet_id
 *   byte   12:     flags
 *   byte   13:     channel  (low 8 bits of xorHash(name) ^ xorHash(psk))
 *   byte   14:     next_hop
 *   byte   15:     relay_node
 *   bytes 16..N-1: AES-CTR(payload of meshtastic.Data protobuf)
 *
 * Nonce layout (16 bytes for AES-CTR):
 *   bytes  0..7:   packet_id (uint64 LE; the upper 32 bits are 0 OTA)
 *   bytes  8..11:  from_node (uint32 LE)
 *   bytes 12..15:  block counter, big-endian, starts at 0
 *                  -- OpenSSL CTR mode increments the full IV as a
 *                     big-endian counter, which only changes the last
 *                     four bytes for any LoRa-sized payload.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "mesh_packet.h"
#include "protobuf.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void parse_header(const uint8_t *frame, mesh_event_t *ev)
{
    ev->header.to         = rd_le32(frame);
    ev->header.from       = rd_le32(frame + 4);
    ev->header.packet_id  = rd_le32(frame + 8);
    ev->header.flags      = frame[12];
    ev->header.channel    = frame[13];
    ev->header.next_hop   = frame[14];
    ev->header.relay_node = frame[15];

    ev->hop_limit = ev->header.flags & MESH_FLAG_HOP_LIMIT_MASK;
    ev->hop_start = (ev->header.flags & MESH_FLAG_HOP_START_MASK)
                    >> MESH_FLAG_HOP_START_SHIFT;
    ev->want_ack  = (ev->header.flags & MESH_FLAG_WANT_ACK_MASK) != 0;
    ev->via_mqtt  = (ev->header.flags & MESH_FLAG_VIA_MQTT_MASK) != 0;
}

static void build_nonce(uint8_t nonce[16], uint32_t packet_id, uint32_t from_node)
{
    /* packet_id (8 bytes LE), from_node (4 bytes LE), counter (4 bytes BE = 0). */
    memset(nonce, 0, 16);
    nonce[0] = (uint8_t)(packet_id      );
    nonce[1] = (uint8_t)(packet_id >>  8);
    nonce[2] = (uint8_t)(packet_id >> 16);
    nonce[3] = (uint8_t)(packet_id >> 24);
    /* nonce[4..7] = upper 32 bits of packet_id, which Meshtastic OTA leaves zero. */
    nonce[8]  = (uint8_t)(from_node      );
    nonce[9]  = (uint8_t)(from_node >>  8);
    nonce[10] = (uint8_t)(from_node >> 16);
    nonce[11] = (uint8_t)(from_node >> 24);
    /* nonce[12..15] = counter, BE, starts at 0 */
}

static int aes_ctr_decrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *iv,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out)
{
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_ctr();
    else if (key_len == 32) cipher = EVP_aes_256_ctr();
    else return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1;
    int outlen = 0, finlen = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out, &outlen, in, (int)in_len) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + outlen, &finlen) != 1) goto done;
    rc = outlen + finlen;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Parse the inner Data envelope (meshtastic.Data) into mesh_event_t.
 * Returns true if portnum is plausible. */
static bool parse_data_envelope(const uint8_t *buf, size_t len, mesh_event_t *ev)
{
    const uint8_t *p   = buf;
    const uint8_t *end = buf + len;

    ev->portnum       = 0;
    ev->payload       = NULL;
    ev->payload_len   = 0;
    ev->request_id    = 0;
    ev->reply_id      = 0;
    ev->want_response = false;

    while (p < end) {
        uint32_t fld, wt;
        if (!pb_read_tag(&p, end, &fld, &wt)) return false;
        switch (fld) {
        case 1: { /* portnum (PortNum enum, varint) */
            uint64_t v;
            if (!pb_read_varint(&p, end, &v)) return false;
            ev->portnum = (uint32_t)v;
            break;
        }
        case 2: { /* payload (bytes) */
            const uint8_t *bp; size_t blen;
            if (!pb_read_length(&p, end, &bp, &blen)) return false;
            ev->payload     = bp;
            ev->payload_len = blen;
            break;
        }
        case 3: { /* want_response (bool varint) */
            uint64_t v;
            if (!pb_read_varint(&p, end, &v)) return false;
            ev->want_response = v != 0;
            break;
        }
        case 4: { /* dest (uint32 varint) -- for direct messages */
            if (!pb_skip_value(&p, end, wt)) return false;
            break;
        }
        case 5: { /* source (uint32 varint) -- for direct messages */
            if (!pb_skip_value(&p, end, wt)) return false;
            break;
        }
        case 6: { /* request_id (fixed32) */
            uint32_t v;
            if (!pb_read_fixed32(&p, end, &v)) return false;
            ev->request_id = v;
            break;
        }
        case 7: { /* reply_id (fixed32) */
            uint32_t v;
            if (!pb_read_fixed32(&p, end, &v)) return false;
            ev->reply_id = v;
            break;
        }
        default:
            if (!pb_skip_value(&p, end, wt)) return false;
            break;
        }
    }

    /* sanity-check portnum: known port or in plausible PortNum range. */
    if (ev->portnum > 1024) return false;
    return true;
}

int mesh_packet_decode(const uint8_t *frame, size_t frame_len,
                       const keyset_t *keys,
                       mesh_event_cb_t cb, void *user)
{
    return mesh_packet_decode_with_meta(frame, frame_len, 0.0f, 0.0f, keys, cb, user);
}

int mesh_packet_decode_with_meta(const uint8_t *frame, size_t frame_len,
                                 float rssi_db, float snr_db,
                                 const keyset_t *keys,
                                 mesh_event_cb_t cb, void *user)
{
    if (!frame || frame_len < MESH_HEADER_BYTES) return -1;

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    parse_header(frame, &ev);
    ev.rssi_db = rssi_db;
    ev.snr_db  = snr_db;

    const uint8_t *cipher = frame + MESH_HEADER_BYTES;
    size_t         cipher_len = frame_len - MESH_HEADER_BYTES;

    /* No payload? Just emit the header (e.g., a routing-only ack). */
    if (cipher_len == 0) {
        ev.decrypted = true;  /* nothing to decrypt */
        if (cb) cb(&ev, user);
        return 0;
    }

    /* Look up candidate keys by channel-hash byte. Hold the keyset
     * read lock for the lookup-and-decrypt sequence so a concurrent
     * /api/keys POST can't move bucket entries out from under us. */
    bool emitted = false;
    if (keys) {
        keyset_rdlock((keyset_t *)keys);
        const int8_t *bucket = keyset_lookup(keys, ev.header.channel);
        uint8_t nonce[16];
        build_nonce(nonce, ev.header.packet_id, ev.header.from);

        uint8_t plaintext[512];
        size_t  use_len = cipher_len > sizeof(plaintext) ? sizeof(plaintext) : cipher_len;
        if (cipher_len > sizeof(plaintext)) {
            extern int verbose;
            if (verbose) {
                fprintf(stderr, "mesh_packet: ciphertext %zu bytes exceeds %zu plaintext buffer; truncating\n",
                        cipher_len, sizeof(plaintext));
            }
        }

        for (int i = 0; bucket && bucket[i] >= 0 && i < 8; ++i) {
            const keyset_entry_t *e = keyset_get(keys, bucket[i]);
            if (!e) continue;

            if (e->psk_len == 0) {
                /* "none" -- treat ciphertext as plaintext directly */
                memcpy(plaintext, cipher, use_len);
            } else {
                int n = aes_ctr_decrypt(e->psk, e->psk_len, nonce,
                                         cipher, use_len, plaintext);
                if (n < 0) continue;
            }

            mesh_event_t cand = ev;
            if (parse_data_envelope(plaintext, use_len, &cand)) {
                cand.decrypted = true;
                strncpy(cand.channel_name, e->channel_name,
                        sizeof(cand.channel_name) - 1);
                if (cb) cb(&cand, user);
                emitted = true;
                break;
            }
        }
        keyset_rdunlock((keyset_t *)keys);
    }

    if (!emitted && cb) {
        ev.decrypted = false;
        cb(&ev, user);
    }
    return 0;
}
