/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * test_iq_ring -- unit test for the raw-IQ ring buffer used by Phase 3
 * scan-then-focus. Covers:
 *   1. small linear append + get_window byte-exact readback
 *   2. wrap: get_window across the wrap point
 *   3. ageing: requesting a window older than the live range returns the
 *      truncated tail and reports the correct number of copied samples
 *   4. one-shot append larger than capacity: only the trailing capacity
 *      samples survive; the prefix is reported as aged out
 *   5. float / cf32 format round trips
 *
 * Pass/fail is reported to stderr; exit code 0 on full pass, 1 on first
 * failure.
 */

#include "../iq_ring.h"
#include "../sdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
        return 1; \
    } \
} while (0)

static int test_linear_int8(void)
{
    iq_ring_t *r = iq_ring_create(1024, SAMPLE_FMT_INT8);
    CHECK(r, "iq_ring_create int8");

    int8_t in[256 * 2];
    for (int i = 0; i < 256; ++i) { in[2*i] = (int8_t)i; in[2*i+1] = (int8_t)-i; }

    uint64_t start = iq_ring_append(r, in, 256);
    CHECK(start == 0, "first append start_idx == 0");

    uint64_t oldest, newest;
    iq_ring_live_range(r, &oldest, &newest);
    CHECK(oldest == 0 && newest == 256, "live range [0..256)");

    int8_t out[256 * 2] = {0};
    size_t n = iq_ring_get_window(r, 0, 256, out);
    CHECK(n == 256, "got 256 samples back");
    CHECK(memcmp(in, out, sizeof in) == 0, "linear int8 byte-exact");

    /* partial window inside live range */
    size_t n2 = iq_ring_get_window(r, 100, 50, out);
    CHECK(n2 == 50, "partial window 50 samples");
    for (int i = 0; i < 50; ++i) {
        CHECK(out[2*i]   == (int8_t)(100 + i), "partial byte I");
        CHECK(out[2*i+1] == (int8_t)-(100 + i), "partial byte Q");
    }
    iq_ring_destroy(r);
    return 0;
}

static int test_wrap_int8(void)
{
    /* Capacity small enough to force wraparound mid-test. */
    iq_ring_t *r = iq_ring_create(300, SAMPLE_FMT_INT8);
    CHECK(r, "iq_ring_create wrap");

    /* Fill, then push more so we wrap. */
    int8_t in[500 * 2];
    for (int i = 0; i < 500; ++i) { in[2*i] = (int8_t)(i & 0x7f); in[2*i+1] = (int8_t)((-i) & 0x7f); }

    iq_ring_append(r, in,         200);          /* writes 0..200 */
    iq_ring_append(r, in + 200*2, 200);          /* writes 200..400; ring still not full (cap=300) -> 0..100 aged out */
    iq_ring_append(r, in + 400*2, 100);          /* writes 400..500; ring is full, oldest=200 */

    uint64_t oldest, newest;
    iq_ring_live_range(r, &oldest, &newest);
    CHECK(oldest == 200 && newest == 500, "wrap live range [200..500)");

    int8_t out[300 * 2] = {0};
    size_t n = iq_ring_get_window(r, 200, 300, out);
    CHECK(n == 300, "got 300 samples after wrap");
    CHECK(memcmp(in + 200*2, out, 300 * 2) == 0, "wrap bytes match");

    /* request a window that straddles the wrap from inside the ring */
    int8_t out2[150 * 2] = {0};
    size_t n2 = iq_ring_get_window(r, 350, 150, out2);
    CHECK(n2 == 150, "post-wrap partial");
    CHECK(memcmp(in + 350*2, out2, 150 * 2) == 0, "post-wrap bytes");

    iq_ring_destroy(r);
    return 0;
}

static int test_ageout(void)
{
    iq_ring_t *r = iq_ring_create(100, SAMPLE_FMT_INT8);
    CHECK(r, "iq_ring_create ageout");
    int8_t in[200 * 2];
    for (int i = 0; i < 200; ++i) { in[2*i] = (int8_t)(i & 0x7f); in[2*i+1] = 0; }
    iq_ring_append(r, in, 200);                  /* batch larger than cap */

    uint64_t oldest, newest;
    iq_ring_live_range(r, &oldest, &newest);
    CHECK(oldest == 100 && newest == 200, "after over-cap append live=[100..200)");

    /* requesting from sample 50 (aged-out) for 100 samples: should return
     * only the slice [100..150) -- the part still alive. */
    int8_t out[100 * 2] = {0};
    size_t n = iq_ring_get_window(r, 50, 100, out);
    CHECK(n == 50, "aged-out portion truncated");
    CHECK(memcmp(in + 100*2, out, 50 * 2) == 0, "aged-out tail correct");

    /* sample 250 is in the future */
    size_t n2 = iq_ring_get_window(r, 250, 10, out);
    CHECK(n2 == 0, "future window returns 0");

    iq_ring_destroy(r);
    return 0;
}

static int test_float(void)
{
    iq_ring_t *r = iq_ring_create(512, SAMPLE_FMT_FLOAT);
    CHECK(r, "iq_ring_create float");
    float in[128 * 2];
    for (int i = 0; i < 128; ++i) { in[2*i] = (float)i * 0.5f; in[2*i+1] = (float)(-i) * 0.25f; }
    iq_ring_append(r, in, 128);
    float out[128 * 2] = {0};
    size_t n = iq_ring_get_window(r, 0, 128, out);
    CHECK(n == 128, "got 128 float samples");
    CHECK(memcmp(in, out, sizeof in) == 0, "float bytes exact");
    iq_ring_destroy(r);
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_linear_int8();        if (rc) return rc;
    rc |= test_wrap_int8();          if (rc) return rc;
    rc |= test_ageout();             if (rc) return rc;
    rc |= test_float();              if (rc) return rc;
    fprintf(stderr, "test_iq_ring: PASS (4 tests)\n");
    return 0;
}
