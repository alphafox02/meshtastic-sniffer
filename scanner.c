/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: off-grid LoRa discovery (energy-based v1).
 *
 * Pipeline:
 *   wideband samples -> N-point FFT (every K input blocks)
 *                       -> rolling magnitude history
 *                       -> peak detector with adaptive noise floor
 *                       -> exclude bins covered by the configured grid
 *                       -> rate-limit + dedupe per peak
 *                       -> on_discovery callback
 *
 */

#include "scanner.h"
#include "fftw_lock.h"

#include <complex.h>
#include <fftw3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KNOWN_GRID_MAX     CHANNELIZER_MAX_CHANNELS_FOR_SCANNER
#define DISCOVERY_LIMIT    64

#ifndef CHANNELIZER_MAX_CHANNELS_FOR_SCANNER
#define CHANNELIZER_MAX_CHANNELS_FOR_SCANNER 256
#endif

typedef struct {
    uint64_t f_hz;
    int      bw_hz;
} known_chan_t;

typedef struct {
    uint64_t f_hz;
    time_t   first_seen;
    time_t   last_seen;
    uint32_t hits;
} discovery_t;

struct scanner {
    uint64_t f_center;
    uint32_t samp_rate;
    int      fft_size;

    /* FFT state */
    fftwf_complex *fft_in;
    fftwf_complex *fft_out;
    fftwf_plan     plan;
    int            input_count;       /* samples accumulated towards next FFT */
    float          power_avg[16384];  /* per-bin EWMA -- max fft_size we tolerate */
    float          power_inst[16384]; /* current frame */

    /* Frame counter for rate control. */
    int            frames_until_emit; /* run peakfind every N FFTs */
    int            frame_counter;

    /* Known grid (for exclusion). */
    known_chan_t   grid[KNOWN_GRID_MAX];
    int            grid_count;

    /* Discovery dedupe. */
    discovery_t    discoveries[DISCOVERY_LIMIT];
    int            disc_count;

    scanner_cb_t   cb;
    void          *user;
};

/* ---- Lifecycle ---- */

scanner_t *scanner_create(uint64_t f_center, uint32_t samp_rate, int fft_size)
{
    if (fft_size < 64 || fft_size > 16384) return NULL;
    /* power-of-two preferred but not required for FFTW. */
    scanner_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->f_center  = f_center;
    s->samp_rate = samp_rate;
    s->fft_size  = fft_size;
    s->fft_in    = fftwf_alloc_complex(fft_size);
    s->fft_out   = fftwf_alloc_complex(fft_size);
    if (!s->fft_in || !s->fft_out) { scanner_destroy(s); return NULL; }
    fftw_planner_lock();
    s->plan = fftwf_plan_dft_1d(fft_size, s->fft_in, s->fft_out,
                                FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_planner_unlock();
    s->frames_until_emit = (int)(samp_rate / (uint32_t)fft_size / 4); /* 4 Hz update */
    if (s->frames_until_emit < 1) s->frames_until_emit = 1;
    return s;
}

void scanner_destroy(scanner_t *s)
{
    if (!s) return;
    if (s->plan) {
        fftw_planner_lock();
        fftwf_destroy_plan(s->plan);
        fftw_planner_unlock();
    }
    fftwf_free(s->fft_in);
    fftwf_free(s->fft_out);
    free(s);
}

int scanner_snapshot(const scanner_t *s, float *out, int max)
{
    if (!s || !out || max < s->fft_size) return 0;
    int N = s->fft_size, half = N / 2;
    /* fftshift: out[i] = power_avg[(i + half) % N] */
    for (int i = 0; i < N; ++i) out[i] = s->power_avg[(i + half) % N];
    return N;
}

void scanner_set_callback(scanner_t *s, scanner_cb_t cb, void *user)
{
    if (!s) return;
    s->cb = cb; s->user = user;
}

void scanner_set_known_grid(scanner_t *s,
                            const uint64_t *freqs_hz, const int *bw_hz, int n)
{
    if (!s) return;
    if (n > KNOWN_GRID_MAX) n = KNOWN_GRID_MAX;
    s->grid_count = n;
    for (int i = 0; i < n; ++i) {
        s->grid[i].f_hz  = freqs_hz[i];
        s->grid[i].bw_hz = bw_hz[i];
    }
}

/* ---- Internals ---- */

static int bin_to_freq_offset_hz(const scanner_t *s, int bin)
{
    int half = s->fft_size / 2;
    int idx  = (bin >= half) ? bin - s->fft_size : bin;     /* fftshift */
    return (int)((double)idx * (double)s->samp_rate / (double)s->fft_size);
}

static bool freq_in_known_grid(const scanner_t *s, uint64_t f_hz)
{
    for (int i = 0; i < s->grid_count; ++i) {
        uint64_t low  = s->grid[i].f_hz - (uint64_t)(s->grid[i].bw_hz / 2);
        uint64_t high = s->grid[i].f_hz + (uint64_t)(s->grid[i].bw_hz / 2);
        if (f_hz >= low && f_hz <= high) return true;
    }
    return false;
}

static discovery_t *discovery_get_or_make(scanner_t *s, uint64_t f_hz)
{
    /* simple linear scan -- DISCOVERY_LIMIT is small */
    for (int i = 0; i < s->disc_count; ++i) {
        /* dedupe within a 50 kHz window so adjacent FFT frames don't multi-emit */
        int64_t diff = (int64_t)f_hz - (int64_t)s->discoveries[i].f_hz;
        if (diff < 0) diff = -diff;
        if (diff < 50000) return &s->discoveries[i];
    }
    if (s->disc_count >= DISCOVERY_LIMIT) return NULL;
    discovery_t *d = &s->discoveries[s->disc_count++];
    d->f_hz       = f_hz;
    d->first_seen = time(NULL);
    d->hits       = 0;
    return d;
}

static void run_peakfind(scanner_t *s)
{
    int N = s->fft_size;

    /* noise floor: cheap median estimate via mean of bottom 25% bins. */
    float local[1024];
    int   n_samp = N < 1024 ? N : 1024;
    int   stride = N / n_samp;
    for (int i = 0; i < n_samp; ++i) local[i] = s->power_avg[i * stride];
    /* partial sort: pick the (n_samp/4)-th smallest */
    /* shell-sort small array for simplicity */
    for (int gap = n_samp/2; gap > 0; gap /= 2)
        for (int i = gap; i < n_samp; ++i) {
            float t = local[i]; int j = i;
            while (j >= gap && local[j-gap] > t) { local[j] = local[j-gap]; j -= gap; }
            local[j] = t;
        }
    float noise = local[n_samp / 4];
    if (noise < 1e-12f) noise = 1e-12f;

    /* peak detect: any bin > 10x noise floor */
    float thresh = noise * 10.0f;
    for (int k = 0; k < N; ++k) {
        if (s->power_avg[k] < thresh) continue;
        /* ignore DC region (likely IQ imbalance) */
        if (abs(k - N/2) < 8) continue;
        /* require local maximum: stronger than +/-2 neighbors */
        int strict = 1;
        for (int j = -2; j <= 2 && strict; ++j) {
            if (j == 0) continue;
            int kk = k + j; if (kk < 0) kk += N; if (kk >= N) kk -= N;
            if (s->power_avg[kk] >= s->power_avg[k]) strict = 0;
        }
        if (!strict) continue;

        int off = bin_to_freq_offset_hz(s, k);
        uint64_t f_hz = s->f_center + off;
        if (freq_in_known_grid(s, f_hz)) continue;

        discovery_t *d = discovery_get_or_make(s, f_hz);
        if (!d) continue;
        d->last_seen = time(NULL);
        ++d->hits;

        if (d->hits == 3 && s->cb) {
            /* announce after 3 confirmations to avoid spurious one-frame spikes.
             *
             * Estimate actual occupied bandwidth: walk outward from the peak
             * until the bin power drops below peak/10 (-10 dB skirt). The
             * single-bin Hz width was a misleading number -- a strong CW carrier
             * looked the same as a 250 kHz LoRa chirp because both light up one
             * bin per FFT frame. With a real BW estimate we can require the
             * detection to look at least LoRa-shaped (>= 50 kHz wide) and skip
             * narrowband stuff (CW beacons, FM pilot tones, IM products). */
            const float bin_hz   = (float)((double)s->samp_rate / (double)s->fft_size);
            const float peak_pow = s->power_avg[k];
            const float skirt    = peak_pow * 0.1f; /* -10 dB */
            int left = 0, right = 0;
            for (int j = 1; j <= s->fft_size / 4; ++j) {
                int kk = k - j; if (kk < 0) kk += s->fft_size;
                if (s->power_avg[kk] < skirt) break;
                left = j;
            }
            for (int j = 1; j <= s->fft_size / 4; ++j) {
                int kk = k + j; if (kk >= s->fft_size) kk -= s->fft_size;
                if (s->power_avg[kk] < skirt) break;
                right = j;
            }
            const float bw_est = (float)(left + right + 1) * bin_hz;
            /* LoRa minimum BW preset is 62.5 kHz -- give a margin and require
             * >= 50 kHz to fire. Caller can still see narrower stuff via
             * --scan or the spectrum tab; we just won't promote-to-alert it. */
            if (bw_est < 50000.0f) continue;
            scanner_discovery_t disc = {
                .f_hz           = d->f_hz,
                .snr_db         = 10.0f * log10f(peak_pow / noise),
                .bw_hz_estimate = bw_est,
                .sf_estimate    = 0,
                .cr_estimate    = 0,
            };
            s->cb(&disc, s->user);
        }
    }
}

/* Take one full FFT frame and update internal state. */
static void process_frame(scanner_t *s)
{
    fftwf_execute(s->plan);
    float complex *out = (float complex *)s->fft_out;
    const float alpha = 0.05f;
    for (int k = 0; k < s->fft_size; ++k) {
        float r = crealf(out[k]), im = cimagf(out[k]);
        s->power_inst[k] = r * r + im * im;
        /* Live EWMA so the spectrum tab reflects every frame, not just
         * every peakfind cycle. */
        s->power_avg[k] = (1.0f - alpha) * s->power_avg[k] + alpha * s->power_inst[k];
    }

    if (++s->frame_counter >= s->frames_until_emit) {
        s->frame_counter = 0;
        run_peakfind(s);
    }
}

void scanner_feed_int8(scanner_t *s, const int8_t *iq_pairs, size_t n_complex)
{
    if (!s) return;
    float complex *buf = (float complex *)s->fft_in;
    const float scale  = 1.0f / 127.0f;
    for (size_t i = 0; i < n_complex; ++i) {
        buf[s->input_count++] = (float)iq_pairs[2*i] * scale +
                                I * (float)iq_pairs[2*i + 1] * scale;
        if (s->input_count == s->fft_size) {
            process_frame(s);
            s->input_count = 0;
        }
    }
}

void scanner_feed_float(scanner_t *s, const float complex *iq, size_t n_complex)
{
    if (!s) return;
    float complex *buf = (float complex *)s->fft_in;
    for (size_t i = 0; i < n_complex; ++i) {
        buf[s->input_count++] = iq[i];
        if (s->input_count == s->fft_size) {
            process_frame(s);
            s->input_count = 0;
        }
    }
}
