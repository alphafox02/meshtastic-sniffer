/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * iq_ring -- absolute-indexed raw IQ ring buffer. The wideband scanner
 * detects a preamble lock, emits a sample-index range, and the focused
 * worker reads that range back out via iq_ring_get_window().
 *
 * Sample index space is uint64_t and monotonic from the moment the ring
 * is created. Wrap math uses 64-bit subtraction so the comparison stays
 * correct even after multi-day captures.
 */

#include "iq_ring.h"
#include "sdr.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct iq_ring {
    pthread_mutex_t mu;
    int       format;          /* SAMPLE_FMT_INT8 or SAMPLE_FMT_FLOAT */
    size_t    bps;             /* bytes per IQ pair: 2 (int8) or 8 (float) */
    size_t    capacity;        /* number of IQ pairs the buffer holds */
    uint8_t  *data;            /* capacity * bps bytes */
    uint64_t  total_written;   /* monotonic; absolute count of appended samples */
};

size_t iq_ring_bytes_per_sample(int format)
{
    if (format == SAMPLE_FMT_FLOAT) return sizeof(float) * 2;
    return sizeof(int8_t) * 2;
}

iq_ring_t *iq_ring_create(size_t capacity_samples, int format)
{
    if (capacity_samples == 0) return NULL;
    if (format != SAMPLE_FMT_INT8 && format != SAMPLE_FMT_FLOAT) return NULL;

    iq_ring_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->format = format;
    r->bps    = iq_ring_bytes_per_sample(format);
    r->capacity = capacity_samples;
    r->data = malloc(capacity_samples * r->bps);
    if (!r->data) { free(r); return NULL; }
    pthread_mutex_init(&r->mu, NULL);
    return r;
}

void iq_ring_destroy(iq_ring_t *r)
{
    if (!r) return;
    pthread_mutex_destroy(&r->mu);
    free(r->data);
    free(r);
}

uint64_t iq_ring_append(iq_ring_t *r, const void *samples, size_t nsamp)
{
    if (!r || !samples || nsamp == 0) return r ? r->total_written : 0;
    pthread_mutex_lock(&r->mu);
    uint64_t start_idx = r->total_written;

    /* If the batch is bigger than the ring, only the trailing `capacity`
     * samples survive -- we still report start_idx as the absolute index
     * of the first sample handed to us, so callers (and get_window) can
     * trust the absolute timeline. */
    size_t to_store = nsamp;
    size_t src_skip = 0;
    if (to_store > r->capacity) {
        src_skip = to_store - r->capacity;
        to_store = r->capacity;
    }

    const uint8_t *src = (const uint8_t *)samples + src_skip * r->bps;
    uint64_t store_first = start_idx + src_skip;
    size_t pos = (size_t)(store_first % (uint64_t)r->capacity);

    size_t first_chunk = r->capacity - pos;
    if (first_chunk > to_store) first_chunk = to_store;
    memcpy(r->data + pos * r->bps, src, first_chunk * r->bps);
    if (to_store > first_chunk) {
        memcpy(r->data, src + first_chunk * r->bps,
               (to_store - first_chunk) * r->bps);
    }

    r->total_written += (uint64_t)nsamp;
    pthread_mutex_unlock(&r->mu);
    return start_idx;
}

size_t iq_ring_get_window(const iq_ring_t *r,
                          uint64_t start_sample, size_t nsamp,
                          void *out)
{
    if (!r || !out || nsamp == 0) return 0;
    iq_ring_t *rw = (iq_ring_t *)r;
    pthread_mutex_lock(&rw->mu);

    uint64_t total = r->total_written;
    uint64_t oldest = (total > (uint64_t)r->capacity)
                    ? (total - (uint64_t)r->capacity) : 0;
    uint64_t end = start_sample + (uint64_t)nsamp;
    if (end > total) end = total;
    if (start_sample < oldest) start_sample = oldest;
    if (end <= start_sample) {
        pthread_mutex_unlock(&rw->mu);
        return 0;
    }
    size_t copy_n = (size_t)(end - start_sample);

    size_t pos = (size_t)(start_sample % (uint64_t)r->capacity);
    uint8_t *dst = (uint8_t *)out;
    size_t first_chunk = r->capacity - pos;
    if (first_chunk > copy_n) first_chunk = copy_n;
    memcpy(dst, r->data + pos * r->bps, first_chunk * r->bps);
    if (copy_n > first_chunk) {
        memcpy(dst + first_chunk * r->bps, r->data,
               (copy_n - first_chunk) * r->bps);
    }

    pthread_mutex_unlock(&rw->mu);
    return copy_n;
}

void iq_ring_live_range(const iq_ring_t *r,
                        uint64_t *oldest_out,
                        uint64_t *newest_plus_one_out)
{
    if (!r) {
        if (oldest_out) *oldest_out = 0;
        if (newest_plus_one_out) *newest_plus_one_out = 0;
        return;
    }
    iq_ring_t *rw = (iq_ring_t *)r;
    pthread_mutex_lock(&rw->mu);
    uint64_t total = r->total_written;
    uint64_t oldest = (total > (uint64_t)r->capacity)
                    ? (total - (uint64_t)r->capacity) : 0;
    pthread_mutex_unlock(&rw->mu);
    if (oldest_out) *oldest_out = oldest;
    if (newest_plus_one_out) *newest_plus_one_out = total;
}

uint64_t iq_ring_total_appended(const iq_ring_t *r)
{
    if (!r) return 0;
    iq_ring_t *rw = (iq_ring_t *)r;
    pthread_mutex_lock(&rw->mu);
    uint64_t v = r->total_written;
    pthread_mutex_unlock(&rw->mu);
    return v;
}

int    iq_ring_format(const iq_ring_t *r)   { return r ? r->format : -1; }
size_t iq_ring_capacity(const iq_ring_t *r) { return r ? r->capacity : 0; }
