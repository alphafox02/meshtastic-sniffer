/*
 * meshtastic-sniffer: multi-key dispatch.
 *
 * Holds the user's set of (channel_name, PSK) pairs and routes
 * incoming packets to the right key by precomputed channel hash.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef KEYSET_H
#define KEYSET_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KEYSET_MAX_ENTRIES   64
#define KEYSET_MAX_NAME      32
#define KEYSET_MAX_PSK_BYTES 32      /* 256-bit AES is the largest case */

typedef struct keyset_entry {
    char     channel_name[KEYSET_MAX_NAME];
    uint8_t  psk[KEYSET_MAX_PSK_BYTES];
    size_t   psk_len;        /* 0 = unencrypted, 16 = AES-128, 32 = AES-256 */
    uint8_t  channel_hash;   /* xorHash(name) ^ xorHash(psk) */
} keyset_entry_t;

typedef struct keyset {
    keyset_entry_t  entries[KEYSET_MAX_ENTRIES];
    int             n_entries;

    /* dispatch: hash -> indices into entries[]. each bucket is a
     * tiny list because hash collisions are rare. */
    int8_t          buckets[256][8];   /* -1 terminator */

    /* Reader-writer protection so the web /api/keys POST handler can
     * call keyset_add() while the demod thread is doing keyset_lookup
     * on every received packet. Adds are rare; reads are hot. */
    pthread_rwlock_t lock;
} keyset_t;

keyset_t *keyset_create(void);
void      keyset_destroy(keyset_t *k);

/* Add a single entry. If channel_name is NULL/empty, defaults to
 * "LongFast" (matching upstream firmware default). Returns 0 on
 * success, -1 if full or PSK length unsupported. */
int keyset_add(keyset_t *k, const char *channel_name,
               const uint8_t *psk, size_t psk_len);

/* Parse one CLI/env-var spec (a single entry, no commas):
 *   "ChannelName=SPEC" or "SPEC"
 * where SPEC is "default", "simple0".."simple10", "hex:HHHH...",
 * "base64:....", or "none". Returns 0 on success. */
int keyset_parse_spec(keyset_t *k, const char *spec);

/* Parse a comma- (or semicolon-) separated list of specs. */
int keyset_parse_csv(keyset_t *k, const char *csv);

/* Look up candidate keys by 1-byte channel hash. Returns a list of
 * indices into entries[], terminated by -1.
 * Caller must hold the read lock (keyset_rdlock/rdunlock) for the
 * duration of the lookup-and-decrypt sequence. */
const int8_t *keyset_lookup(const keyset_t *k, uint8_t channel_hash);

const keyset_entry_t *keyset_get(const keyset_t *k, int index);

/* Read-lock helpers for the hot path. Use when looking up + reading
 * an entry from another thread while keyset_add() may be happening
 * concurrently from the web /api/keys handler. */
void keyset_rdlock  (keyset_t *k);
void keyset_rdunlock(keyset_t *k);

void keyset_print(const keyset_t *k);

#endif
