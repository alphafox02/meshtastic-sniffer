/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: delayed best-pick dedup for PFB bin-leakage replicas.
 *
 * Two-tier matching:
 *   Tier 1 -- payload XOR-fold fingerprint with Hamming threshold.
 *             Catches clean / lightly-corrupted replicas. Threshold
 *             loosens from 14 to 22 bits when payload CRC failed.
 *   Tier 2 -- slot+time-adjacency. Runs only when Tier 1 misses.
 *             Catches heavy-corruption cases where bit errors push
 *             fingerprints apart by more than the Tier 1 threshold.
 *             Grounded in the channelizer's RF physics (bin leakage
 *             is bounded in slot range and arrives within microseconds
 *             of the original) rather than byte similarity.
 *
 * The ring is fixed size; clusters are emitted by an external drainer
 * (lives in main.c so it can call into the decode/publish pipeline).
 */

#ifndef DEDUP_H
#define DEDUP_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lora.h"

#define DEDUP_RING_SIZE                 512
#define DEDUP_WINDOW_US                 30000   /* 30 ms emit window */
#define DEDUP_FP_HAMMING_THRESH         14      /* clean replicas */
#define DEDUP_FP_HAMMING_THRESH_CRCFAIL 22      /* CRC-failed replicas */
#define DEDUP_MAX_PAYLOAD               256
#define DEDUP_SLOT_ADJACENCY_US         500     /* Tier-2 time window */
#define DEDUP_SLOT_PROXIMITY            3       /* Tier-2 slot distance */
/* Tier-3 wide-slot window: set to the full DEDUP_WINDOW_US (30 ms)
 * rather than the 200 us RF-event spacing observed in live captures.
 * Reason: the async sink worker pool reorders replica arrivals at
 * dedup_buffer relative to the original RF event order, so monotonic
 * time at dedup_buffer call site can differ by several ms between the
 * CRC-pass winner and its CRC-fail phantoms even when the RF events
 * were 87 us apart. Tying Tier-3 to the existing dedup window keeps
 * "same emission batch" as the semantic. */
#define DEDUP_TIER3_WINDOW_US           DEDUP_WINDOW_US

typedef struct {
    bool                in_use;
    uint64_t            fp;
    int                 sf;
    int                 bw_hz;
    uint64_t            emit_at_us;     /* now_us + WINDOW_US when opened */
    uint64_t            first_seen_t_ns;/* CLOCK_REALTIME ns at first replica */
    /* Highest-SNR replica seen so far for this cluster. */
    float               best_snr_db;
    size_t              best_payload_len;
    uint8_t             best_payload[DEDUP_MAX_PAYLOAD];
    lora_frame_meta_t   best_meta;
    intptr_t            best_user;
    int                 replica_count;
    /* Tier-2 dedup: PFB slot range covered by this cluster's replicas.
     * INT16_MIN sentinel = "no slot info" (file replay or test inputs
     * that don't pass a channelizer slot index). */
    int16_t             min_slot_id;
    int16_t             max_slot_id;
} dedup_entry_t;

/* The shared ring + mutex. Public so the drainer in main.c can read
 * it; do not mutate from outside dedup.c. */
extern dedup_entry_t   g_dedup[DEDUP_RING_SIZE];
extern pthread_mutex_t g_dedup_mu;

/* Inject one replica. Threadsafe. Either folds into an existing
 * cluster (tier 1 fp match, or tier 2 slot+time match) or opens a
 * new one. user = the PFB channel/slot id (>=0) or -1 if unavailable. */
void dedup_buffer(const uint8_t *payload, size_t payload_len,
                  const lora_frame_meta_t *meta, intptr_t user);

/* Test-only: reset the ring to empty. Not safe to call concurrently
 * with dedup_buffer / drainer. */
void dedup_reset_for_test(void);

/* Test-only: monotonic_us override. When non-NULL, dedup_buffer
 * reads time from this function instead of clock_gettime. Pass NULL
 * to restore real time. */
typedef uint64_t (*dedup_clock_fn)(void);
void dedup_set_clock_for_test(dedup_clock_fn fn);

/* Time helpers exposed for the drainer + the rest of main.c. */
uint64_t dedup_monotonic_us(void);
uint64_t dedup_realtime_ns(void);

/* Payload fingerprint -- exposed for tests so synthetic inputs can
 * assert specific Hamming distances. */
uint64_t dedup_payload_fingerprint(const uint8_t *p, size_t n);

/* Stats counters. Bumped from dedup_buffer; read by main.c shutdown to
 * print a summary. Thread-safe via atomic_uint_fast64_t in dedup.c. */
uint64_t dedup_stat_crc_fail_suppressed_near_pass(void);
uint64_t dedup_stat_crc_fail_admitted_no_pass(void);

#endif /* DEDUP_H */
