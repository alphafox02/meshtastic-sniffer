/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: dedup ring + two-tier matching.
 *
 * Extracted from main.c so the matching logic is reachable from
 * standalone tests. Behaviour is preserved exactly; the only change
 * vs. the in-line implementation is the addition of the tier-2
 * slot+time-adjacency fallback after the existing fingerprint match.
 */

#include "dedup.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

dedup_entry_t   g_dedup[DEDUP_RING_SIZE];
pthread_mutex_t g_dedup_mu = PTHREAD_MUTEX_INITIALIZER;

/* Optional test clock. When non-NULL, dedup_buffer reads time from
 * here so tests can drive the time axis deterministically. */
static dedup_clock_fn g_test_clock = NULL;

uint64_t dedup_monotonic_us(void)
{
    if (g_test_clock) return g_test_clock();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

uint64_t dedup_realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* 64-bit XOR-fold of the payload bytes. Two near-identical inputs
 * produce near-identical outputs; a single bit error flips a single
 * bit in the fingerprint. */
uint64_t dedup_payload_fingerprint(const uint8_t *p, size_t n)
{
    uint64_t h = 0;
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t w;
        memcpy(&w, p + i, sizeof(w));
        h ^= w;
        h = (h << 1) | (h >> 63);
    }
    uint64_t tail = 0;
    for (size_t i = (n & ~7ULL); i < n; ++i)
        tail |= (uint64_t)p[i] << ((i - (n & ~7ULL)) * 8);
    return h ^ tail;
}

void dedup_buffer(const uint8_t *payload, size_t payload_len,
                  const lora_frame_meta_t *meta, intptr_t user)
{
    if (!payload || payload_len < 14 || payload_len > DEDUP_MAX_PAYLOAD) return;
    int sf = meta ? meta->sf    : 0;
    int bw = meta ? meta->bw_hz : 0;
    float snr = meta ? meta->snr_db : 0.0f;
    bool crc_bad = meta && meta->has_crc && !meta->payload_crc_ok;
    uint64_t fp = dedup_payload_fingerprint(payload, payload_len);
    uint64_t now_us = dedup_monotonic_us();

    const int thresh = crc_bad ? DEDUP_FP_HAMMING_THRESH_CRCFAIL
                               : DEDUP_FP_HAMMING_THRESH;

    /* slot_id_valid gates Tier-2: file-replay and other non-channelizer
     * sources pass user = -1, which has no meaningful slot proximity. */
    const bool slot_id_valid = (user >= 0 && user < INT16_MAX);
    const int16_t slot_id = slot_id_valid ? (int16_t)user : INT16_MIN;

    pthread_mutex_lock(&g_dedup_mu);
    dedup_entry_t *match = NULL;
    int free_slot = -1;
    /* Tier 1: payload-fingerprint match. */
    for (int i = 0; i < DEDUP_RING_SIZE; ++i) {
        dedup_entry_t *e = &g_dedup[i];
        if (!e->in_use) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (e->sf != sf || e->bw_hz != bw) continue;
        int hd = __builtin_popcountll(e->fp ^ fp);
        if (hd <= thresh) { match = e; break; }
    }
    /* Tier 2: slot+time adjacency fallback for heavy-corruption
     * replicas whose fingerprints drifted past the Hamming threshold.
     * Skipped when the new replica has no slot id (non-channelizer
     * source) or when an entry has no slot info to compare against. */
    if (!match && slot_id_valid) {
        for (int i = 0; i < DEDUP_RING_SIZE; ++i) {
            dedup_entry_t *e = &g_dedup[i];
            if (!e->in_use) continue;
            if (e->sf != sf || e->bw_hz != bw) continue;
            if (e->min_slot_id == INT16_MIN) continue;
            uint64_t cluster_open_us = e->emit_at_us - DEDUP_WINDOW_US;
            if (now_us < cluster_open_us) continue; /* clock skew sentinel */
            if (now_us - cluster_open_us > DEDUP_SLOT_ADJACENCY_US) continue;
            int dist_below = (int)e->min_slot_id - (int)slot_id;
            int dist_above = (int)slot_id - (int)e->max_slot_id;
            if (dist_below > DEDUP_SLOT_PROXIMITY) continue;
            if (dist_above > DEDUP_SLOT_PROXIMITY) continue;
            match = e;
            break;
        }
    }
    if (match) {
        match->replica_count++;
        /* Tournament: prefer "good" (CRC-pass OR no-CRC) over CRC-fail
         * unconditionally; tiebreak on SNR within the same class. The old
         * SNR-only rule let a high-SNR CRC-FAIL phantom replace a CRC-PASS
         * true frame in the same cluster -- benign under serial dispatch
         * (the CRC-pass usually arrived first and won the SNR slot before
         * phantoms surfaced), but non-deterministic under the async sink
         * worker pool where replicas arrive in arbitrary order.
         *
         * lora.c sets payload_crc_ok=true for frames with no CRC field, so
         * `payload_crc_ok` alone is the right "good" predicate (avoids
         * treating implicit-header frames as CRC-fail). */
        bool new_good = meta && meta->payload_crc_ok;
        bool cur_good = match->best_meta.payload_crc_ok;
        bool replace;
        if (new_good && !cur_good)      replace = true;
        else if (!new_good && cur_good) replace = false;
        else                            replace = (snr > match->best_snr_db);
        if (replace) {
            match->best_snr_db      = snr;
            match->best_payload_len = payload_len;
            memcpy(match->best_payload, payload, payload_len);
            if (meta) match->best_meta = *meta;
            match->best_user        = user;
            match->fp               = fp;   /* update to cleaner fp */
        }
        if (slot_id_valid) {
            if (match->min_slot_id == INT16_MIN || slot_id < match->min_slot_id)
                match->min_slot_id = slot_id;
            if (match->max_slot_id == INT16_MIN || slot_id > match->max_slot_id)
                match->max_slot_id = slot_id;
        }
    } else if (free_slot >= 0) {
        dedup_entry_t *e = &g_dedup[free_slot];
        e->in_use           = true;
        e->fp               = fp;
        e->sf               = sf;
        e->bw_hz            = bw;
        e->emit_at_us       = now_us + DEDUP_WINDOW_US;
        e->first_seen_t_ns  = dedup_realtime_ns();
        e->best_snr_db      = snr;
        e->best_payload_len = payload_len;
        memcpy(e->best_payload, payload, payload_len);
        if (meta) e->best_meta = *meta;
        e->best_user        = user;
        e->replica_count    = 1;
        e->min_slot_id      = slot_id_valid ? slot_id : INT16_MIN;
        e->max_slot_id      = slot_id_valid ? slot_id : INT16_MIN;
    }
    /* else: ring full -- silently drop. */
    pthread_mutex_unlock(&g_dedup_mu);
}

void dedup_reset_for_test(void)
{
    pthread_mutex_lock(&g_dedup_mu);
    memset(g_dedup, 0, sizeof(g_dedup));
    pthread_mutex_unlock(&g_dedup_mu);
}

void dedup_set_clock_for_test(dedup_clock_fn fn)
{
    g_test_clock = fn;
}
