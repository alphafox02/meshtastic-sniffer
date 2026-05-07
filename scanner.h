/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: off-grid LoRa discovery.
 *
 * Watches the full SDR passband for energy outside the configured
 * channel grid. v1 is an energy detector: periodic wideband FFT,
 * peak find, exclude known-grid frequencies, emit discovery event
 * with peak SNR. Chirp matched-filter shape verification (linear
 * walk across FFT bins over time at one of the 9 (SF,BW) chirp
 * slopes) is a planned refinement to drop the false positive rate.
 *
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <complex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct scanner scanner_t;

typedef struct scanner_discovery {
    uint64_t f_hz;          /* estimated carrier frequency */
    float    snr_db;        /* peak/noise ratio in dB */
    float    bw_hz_estimate;/* width of the peak (rough) */
    /* These start as 0 / unknown and are filled in by the chirp
     * matched filter when implemented. */
    int      sf_estimate;
    int      cr_estimate;
} scanner_discovery_t;

typedef void (*scanner_cb_t)(const scanner_discovery_t *disc, void *user);

scanner_t *scanner_create(uint64_t f_center, uint32_t samp_rate,
                          int fft_size);

/* Provide the configured (frequency, BW) pairs so the scanner can
 * exclude them from "off-grid" reports. Repeated calls replace. */
void scanner_set_known_grid(scanner_t *s,
                            const uint64_t *freqs_hz, const int *bw_hz, int n);

void scanner_set_callback(scanner_t *s, scanner_cb_t cb, void *user);

/* Feed wideband samples (sames flavours as channelizer). Cheap when no
 * known-grid info is set yet. */
void scanner_feed_int8 (scanner_t *s, const int8_t *iq_pairs, size_t n_complex);
void scanner_feed_float(scanner_t *s, const float complex *iq, size_t n_complex);

void scanner_destroy(scanner_t *s);

/* Snapshot the current rolling-EWMA FFT magnitudes into the caller's
 * buffer (length must be at least fft_size returned via the value
 * passed to scanner_create()). Returns the fft_size, or 0 if invalid.
 *
 * Used by the spectrum tab in the web dashboard. Snapshots are
 * fft-shifted (DC at center) so out[N/2] is at f_center. */
int scanner_snapshot(const scanner_t *s, float *out, int max);

#endif
