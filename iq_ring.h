/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Raw-IQ ring buffer fed by the sample pump. Holds the most recent
 * `capacity_samples` IQ pairs in the SDR's native format so a focused
 * decoder can rewind to the start of an event detected by the wideband
 * scanner. Single-writer (sample-pump thread), multi-reader (focused
 * workers); a single mutex serialises both sides.
 */

#ifndef IQ_RING_H
#define IQ_RING_H

#include <stddef.h>
#include <stdint.h>

typedef struct iq_ring iq_ring_t;

/* Create a ring of `capacity_samples` IQ pairs in `format`
 * (SAMPLE_FMT_INT8 or SAMPLE_FMT_FLOAT, from sdr.h). Returns NULL on
 * allocation failure or invalid arguments. */
iq_ring_t *iq_ring_create(size_t capacity_samples, int format);
void       iq_ring_destroy(iq_ring_t *r);

/* Append `nsamp` IQ pairs (bytes in `samples` use the ring's native
 * layout: 2 bytes/pair for INT8, 8 bytes/pair for FLOAT). Returns the
 * absolute sample index of the first appended sample. When more samples
 * are appended than the ring can hold, only the most recent
 * `capacity_samples` survive but the returned start index is still the
 * absolute index of the first sample in this batch -- get_window() will
 * report which prefix has already aged out. */
uint64_t   iq_ring_append(iq_ring_t *r, const void *samples, size_t nsamp);

/* Copy [start_sample, start_sample + nsamp) into `out`. Returns the
 * number of samples actually copied. Less than `nsamp` when part of the
 * requested range has been overwritten (start_sample below the live
 * window) or lies in the future. `out` must be sized for
 * nsamp * iq_ring_bytes_per_sample(format) bytes. */
size_t     iq_ring_get_window(const iq_ring_t *r,
                              uint64_t start_sample, size_t nsamp,
                              void *out);

/* Currently-live range in absolute sample indices:
 * [*oldest_out, *newest_plus_one_out). When the ring has never been
 * written to, both values are zero. */
void       iq_ring_live_range(const iq_ring_t *r,
                              uint64_t *oldest_out,
                              uint64_t *newest_plus_one_out);

/* Total samples ever appended (monotonic). */
uint64_t   iq_ring_total_appended(const iq_ring_t *r);

size_t     iq_ring_bytes_per_sample(int format);
int        iq_ring_format(const iq_ring_t *r);
size_t     iq_ring_capacity(const iq_ring_t *r);

#endif
