/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Unit tests for the two-tier dedup in dedup.c. Covers:
 *   - Tier-1 fingerprint match (existing behaviour, no regression)
 *   - Tier-2 slot+time-adjacency match (heavy-corruption replicas)
 *   - False-positive guards (distant slots, distant time, mismatched SF/BW)
 *   - Edge cases (no slot id, slot range expansion, ring full)
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../dedup.h"
#include "../lora.h"

/* Mock test clock. Tests increment this directly to drive the time axis. */
static uint64_t g_now_us = 1000000ULL;
static uint64_t mock_clock(void) { return g_now_us; }

static int g_test_pass, g_test_fail;
#define EXPECT(cond, msg) do {                              \
    if (cond) { g_test_pass++; }                            \
    else {                                                  \
        g_test_fail++;                                      \
        fprintf(stderr, "  FAIL %s: %s\n", __func__, msg);  \
    }                                                       \
} while (0)

static int count_in_use(void) {
    int n = 0;
    for (int i = 0; i < DEDUP_RING_SIZE; ++i) if (g_dedup[i].in_use) n++;
    return n;
}

static dedup_entry_t *find_in_use(void) {
    for (int i = 0; i < DEDUP_RING_SIZE; ++i) if (g_dedup[i].in_use) return &g_dedup[i];
    return NULL;
}

static void reset(void) {
    dedup_reset_for_test();
    g_now_us = 1000000ULL;
}

/* Build a synthetic payload of N bytes. seed seeds the pseudo-random
 * fill so tests can produce identical or distinct payloads on demand. */
static void make_payload(uint8_t *buf, size_t n, uint32_t seed) {
    uint32_t s = seed * 2654435761u + 1;
    for (size_t i = 0; i < n; ++i) {
        s = s * 1103515245u + 12345u;
        buf[i] = (uint8_t)(s >> 16);
    }
}

/* Make a copy of `buf` with `n_flips` random bits flipped, using a
 * deterministic generator so the same flips happen every run. */
static void flip_bits(uint8_t *buf, size_t n, int n_flips, uint32_t seed) {
    uint32_t s = seed;
    for (int i = 0; i < n_flips; ++i) {
        s = s * 1103515245u + 12345u;
        size_t byte = (s >> 8) % n;
        s = s * 1103515245u + 12345u;
        int bit = (s >> 4) & 7;
        buf[byte] ^= (uint8_t)(1u << bit);
    }
}

/* ---- Tier-1: existing fingerprint match ---- */

static void test_tier1_clean_replicas_fold(void) {
    reset();
    uint8_t buf[64];
    make_payload(buf, sizeof(buf), 1);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 10.0f};
    /* Five identical-payload replicas across slots 100..104 */
    for (int slot = 100; slot < 105; ++slot)
        dedup_buffer(buf, sizeof(buf), &meta, slot);
    EXPECT(count_in_use() == 1, "5 identical payloads should fold to 1 cluster");
    dedup_entry_t *e = find_in_use();
    EXPECT(e && e->replica_count == 5, "replica_count should be 5");
    EXPECT(e && e->min_slot_id == 100, "min_slot_id should be 100");
    EXPECT(e && e->max_slot_id == 104, "max_slot_id should be 104");
}

static void test_tier1_distinct_payloads_separate(void) {
    reset();
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 99);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 10.0f};
    dedup_buffer(a, sizeof(a), &meta, 100);
    dedup_buffer(b, sizeof(b), &meta, 200);
    EXPECT(count_in_use() == 2, "distinct payloads in distant slots stay separate");
}

static void test_tier1_higher_snr_wins(void) {
    reset();
    uint8_t buf[64];
    make_payload(buf, sizeof(buf), 1);
    lora_frame_meta_t lo = {.sf = 11, .bw_hz = 250000, .snr_db = 5.0f};
    lora_frame_meta_t hi = {.sf = 11, .bw_hz = 250000, .snr_db = 20.0f};
    dedup_buffer(buf, sizeof(buf), &lo, 100);
    dedup_buffer(buf, sizeof(buf), &hi, 101);
    dedup_entry_t *e = find_in_use();
    EXPECT(e && e->best_snr_db == 20.0f, "higher-SNR replica becomes the survivor");
    EXPECT(e && e->best_user == 101, "best_user should be the high-SNR replica's slot");
}

/* ---- Tier-2: slot+time adjacency ---- */

static void test_tier2_heavy_corruption_folds_via_slot(void) {
    reset();
    /* Two replicas with totally different payloads (so the
     * fingerprint match fails). Same SF/BW, adjacent slot, same
     * instant. Only Tier 2 can fold them, which is the point. */
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 999);  /* fp distance ~32, well past 22 */
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                              .has_crc = true, .payload_crc_ok = false};
    dedup_buffer(a, sizeof(a), &meta, 100);
    g_now_us += 50;
    dedup_buffer(b, sizeof(b), &meta, 101);
    EXPECT(count_in_use() == 1, "tier-2 should fold heavy-corruption replica in adjacent slot");
    dedup_entry_t *e = find_in_use();
    EXPECT(e && e->replica_count == 2, "replica_count should reflect both replicas");
}

static void test_tier2_far_slot_does_not_fold(void) {
    /* Use TWO COMPLETELY DIFFERENT payloads (different seeds) so the
     * fp distance is ~32 (far past any Tier 1 threshold). The only
     * thing that could fold them would be Tier 2, and the slot
     * distance of 50 should prevent that. */
    reset();
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 999);   /* completely different */
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                              .has_crc = true, .payload_crc_ok = false};
    dedup_buffer(a, sizeof(a), &meta, 100);
    g_now_us += 50;
    dedup_buffer(b, sizeof(b), &meta, 150); /* slot far outside ±3 */
    EXPECT(count_in_use() == 2, "tier-2 must not fold distant-slot replicas");
}

static void test_tier2_old_cluster_does_not_fold(void) {
    reset();
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 999);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                              .has_crc = true, .payload_crc_ok = false};
    dedup_buffer(a, sizeof(a), &meta, 100);
    g_now_us += DEDUP_SLOT_ADJACENCY_US + 100;
    dedup_buffer(b, sizeof(b), &meta, 101);
    EXPECT(count_in_use() == 2, "tier-2 must not fold replicas outside the time window");
}

static void test_tier2_mismatched_sf_does_not_fold(void) {
    reset();
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 999);
    lora_frame_meta_t meta_a = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                                .has_crc = true, .payload_crc_ok = false};
    lora_frame_meta_t meta_b = {.sf = 9,  .bw_hz = 250000, .snr_db = 25.0f,
                                .has_crc = true, .payload_crc_ok = false};
    dedup_buffer(a, sizeof(a), &meta_a, 100);
    g_now_us += 50;
    dedup_buffer(b, sizeof(b), &meta_b, 101);
    EXPECT(count_in_use() == 2, "different SF must keep clusters separate");
}

static void test_tier2_slot_range_expansion(void) {
    /* Five replicas land in slots 100, 101, 102, 103, 104 over 200 µs.
     * After folding, min_slot=100 and max_slot=104. A sixth replica
     * at slot 107 (3 above max) should still fold (within proximity).
     * A seventh replica at slot 108 (4 above max) should NOT fold. */
    reset();
    uint8_t a[64];
    make_payload(a, sizeof(a), 1);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 10.0f,
                              .has_crc = true, .payload_crc_ok = false};
    /* First five with identical payload -> Tier 1 fold */
    for (int slot = 100; slot <= 104; ++slot) {
        dedup_buffer(a, sizeof(a), &meta, slot);
        g_now_us += 10;
    }
    EXPECT(count_in_use() == 1, "5 identical replicas fold via Tier 1");
    dedup_entry_t *e = find_in_use();
    EXPECT(e && e->max_slot_id == 104, "max_slot_id tracks the highest slot");

    /* Sixth replica: completely different payload (no Tier-1 match
     * possible), slot 107 (3 above max=104) -> Tier 2 fold */
    uint8_t b[64];
    make_payload(b, sizeof(b), 999);
    dedup_buffer(b, sizeof(b), &meta, 107);
    EXPECT(count_in_use() == 1, "slot 107 (max+3) should fold via Tier 2 proximity");

    /* Seventh replica: distant slot, totally different payload */
    uint8_t c[64];
    make_payload(c, sizeof(c), 12345);
    dedup_buffer(c, sizeof(c), &meta, 200);  /* far away */
    EXPECT(count_in_use() == 2, "slot 200 (far) opens a new cluster");
}

/* ---- Edge cases ---- */

static void test_no_slot_id_skips_tier2(void) {
    /* user = -1 means "no slot id" (e.g. file replay). Tier 2 should
     * not engage; only Tier 1 fingerprint match applies. Use COMPLETELY
     * different payloads so Tier 1 also cannot match -- otherwise we'd
     * be testing Tier 1, not Tier 2's gate. */
    reset();
    uint8_t a[64], b[64];
    make_payload(a, sizeof(a), 1);
    make_payload(b, sizeof(b), 999);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                              .has_crc = true, .payload_crc_ok = false};
    dedup_buffer(a, sizeof(a), &meta, -1);
    g_now_us += 50;
    dedup_buffer(b, sizeof(b), &meta, -1);
    EXPECT(count_in_use() == 2, "no-slot-id inputs cannot fold via Tier 2");
}

static void test_short_payload_rejected(void) {
    reset();
    uint8_t tiny[8] = {0};
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000};
    dedup_buffer(tiny, sizeof(tiny), &meta, 100);
    EXPECT(count_in_use() == 0, "payloads shorter than 14 bytes are rejected");
}

static void test_oversize_payload_rejected(void) {
    reset();
    uint8_t big[DEDUP_MAX_PAYLOAD + 1] = {0};
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000};
    dedup_buffer(big, sizeof(big), &meta, 100);
    EXPECT(count_in_use() == 0, "payloads larger than DEDUP_MAX_PAYLOAD are rejected");
}

static void test_realworld_phantom_scenario(void) {
    /* Reproduces the close-range scenario from the May 11 session:
     * one physical packet, 7 replicas across slots 109-115, varying
     * bit corruption. Each replica's payload differs from the
     * cleanest one by 15-35 bit flips. Without Tier 2 the existing
     * fingerprint match folds the 15-20 bit-flip replicas via the
     * loosened threshold but lets the 25-35 bit-flip replicas
     * escape as phantoms. With Tier 2 they all fold via slot
     * proximity. */
    reset();
    uint8_t base[100];
    make_payload(base, sizeof(base), 42);
    lora_frame_meta_t meta = {.sf = 11, .bw_hz = 250000, .snr_db = 25.0f,
                              .has_crc = true, .payload_crc_ok = false};
    const int corruption[] = {0, 5, 12, 20, 30, 35, 28};
    const int slots[]      = {110, 111, 112, 113, 114, 115, 109};
    for (size_t i = 0; i < sizeof(slots)/sizeof(slots[0]); ++i) {
        uint8_t buf[100];
        memcpy(buf, base, sizeof(buf));
        if (corruption[i] > 0) flip_bits(buf, sizeof(buf), corruption[i], 1000 + i);
        meta.snr_db = 25.0f - (float)corruption[i] * 0.5f;
        dedup_buffer(buf, sizeof(buf), &meta, slots[i]);
        g_now_us += 20; /* 20 µs between PFB replicas */
    }
    EXPECT(count_in_use() == 1, "real-world 7-replica scenario folds to 1 cluster");
    dedup_entry_t *e = find_in_use();
    EXPECT(e && e->replica_count == 7, "all 7 replicas counted");
    EXPECT(e && e->min_slot_id == 109, "min_slot_id captured");
    EXPECT(e && e->max_slot_id == 115, "max_slot_id captured");
    /* Highest-SNR survivor is the one with 0 bit flips (slot 110, snr=25) */
    EXPECT(e && e->best_snr_db == 25.0f, "best-SNR survivor preserved");
    EXPECT(e && e->best_user == 110, "best_user = slot of cleanest replica");
}

int main(void)
{
    dedup_set_clock_for_test(mock_clock);

    fprintf(stderr, "== Tier-1 (existing behaviour) ==\n");
    test_tier1_clean_replicas_fold();
    test_tier1_distinct_payloads_separate();
    test_tier1_higher_snr_wins();

    fprintf(stderr, "== Tier-2 (slot+time adjacency) ==\n");
    test_tier2_heavy_corruption_folds_via_slot();
    test_tier2_far_slot_does_not_fold();
    test_tier2_old_cluster_does_not_fold();
    test_tier2_mismatched_sf_does_not_fold();
    test_tier2_slot_range_expansion();

    fprintf(stderr, "== Edge cases ==\n");
    test_no_slot_id_skips_tier2();
    test_short_payload_rejected();
    test_oversize_payload_rejected();

    fprintf(stderr, "== Real-world scenario ==\n");
    test_realworld_phantom_scenario();

    fprintf(stderr, "\n== Results: %d passed, %d failed ==\n",
            g_test_pass, g_test_fail);
    return g_test_fail == 0 ? 0 : 1;
}
