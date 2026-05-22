/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: polyphase channelizer.
 *
 * Replaces the old per-channel cascade DDC with one polyphase filterbank
 * per unique channel BW. The PFB processes the SDR stream once at full
 * rate and produces M = SDR_rate / BW critically-sampled outputs in
 * parallel, with adjacent channels isolated by the prototype filter
 * (Hamming-windowed sinc, ~-43 dB sidelobes).
 *
 * For Meshtastic on the US ISM band at 20 Msps:
 *   500 kHz BW -> M=40, supports SHORT_TURBO + LONG_TURBO
 *   250 kHz BW -> M=80, supports SHORT_FAST/SLOW + MEDIUM_* + LONG_FAST
 *   125 kHz BW -> M=160, supports LONG_MOD + LONG_SLOW
 * Three PFBs total, all running off the same input stream. Each PFB's
 * pre-shift NCO aligns its output bin grid to the corresponding
 * Meshtastic channel grid (Meshtastic BW=N kHz channels are at
 * 902 + N/2 + (n-1)*N kHz, so the grid is offset by N/2 kHz from a
 * naively-centered FFT bin grid).
 *
 * Cost per input sample: 3 PFBs * (L taps + log2 M) ops ≈ 50 ops -- vs
 * the cascade's ~200 ops per channel * 256 channels = 50,000 ops. Three
 * orders of magnitude cheaper at full US-band coverage.
 *
 */

#include "channelizer.h"
#include "options.h"
#include "pfb.h"

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_OPENMP)
#include <omp.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define MAX_PFB_GROUPS    8     /* one PFB per unique BW; far more than the
                                 * 3 BWs Meshtastic uses, leaves headroom. */
#define PFB_TAPS_PER_BR   12    /* L taps per polyphase branch. 12 gives
                                 * ~-43 dB worst-case adjacent leakage. */

/* PFB pre-shift policy: pre-shift = (first_channel_freq - sdr_center).
 * That puts the first channel registered for this BW on bin 0; every
 * subsequent channel for the same BW lands on its integer-bin offset
 * from there. Works for synthetic (user picks center == channel) and
 * for full-band scans (first channel = lowest, others +n*BW above).
 * No assumption about the Meshtastic grid baseline -- the caller drives. */

typedef struct {
    int             active;
    int             bw_hz;        /* every channel in this group shares this BW */
    int             os_factor;    /* every channel in this group shares this os */
    pfb_t          *pfb;
    /* Frequency of FFT bin 0 = f_center + pre_shift; channels at
     * (bin_0_freq + bin*bw_hz) (mod samp_rate) for bin = 0..M-1. */
    double          bin_0_freq;
    double          samp_rate;    /* mirror of channelizer's samp_rate */
} pfb_group_t;

typedef struct chan_state {
    int               id;
    channel_cfg_t     cfg;
    int               group_idx;
    int               bin;
} chan_state_t;

struct channelizer {
    uint64_t        f_center;
    uint32_t        samp_rate;
    int             n_channels;
    chan_state_t   *channels[CHANNELIZER_MAX_CHANNELS];
    int             n_groups;
    pfb_group_t     groups[MAX_PFB_GROUPS];
    /* Shared cs8->cf32 workbuf for the int8 input path. NOT thread-local
     * because the OpenMP worker threads must read what the master thread
     * wrote (worker threads have their own __thread copies which would
     * be NULL otherwise). */
    float complex  *workbuf;
    size_t          workbuf_cap;
};

/* PFB callback adapter: just unwrap to the per-channel callback the
 * upper layer registered via channel_cfg.on_baseband. */
static void pfb_emit_adapter(int channel_id, const float complex *iq,
                             size_t n, void *user)
{
    chan_state_t *s = (chan_state_t *)user;
    if (s && s->cfg.on_baseband)
        s->cfg.on_baseband(channel_id, iq, n, s->cfg.user);
}

/* Find an existing PFB group for this (BW, os_factor) combo, or create
 * one. On creation the pre-shift is set so that the just-added channel
 * lands on bin 0; subsequent channels in the same group fall on their
 * integer-bin offset from there. */
static int find_or_create_group(channelizer_t *c, int bw_hz, int os_factor,
                                double first_channel_hz)
{
    for (int g = 0; g < c->n_groups; ++g) {
        if (c->groups[g].active &&
            c->groups[g].bw_hz == bw_hz &&
            c->groups[g].os_factor == os_factor)
            return g;
    }
    if (c->n_groups >= MAX_PFB_GROUPS) {
        if (verbose)
            fprintf(stderr, "channelizer: hit MAX_PFB_GROUPS=%d\n", MAX_PFB_GROUPS);
        return -1;
    }
    if (c->samp_rate % (uint32_t)bw_hz != 0) {
        if (verbose)
            fprintf(stderr, "channelizer: non-integer M for bw=%d at rate=%u\n",
                    bw_hz, c->samp_rate);
        return -1;
    }
    int M = (int)(c->samp_rate / (uint32_t)bw_hz);
    if (M < 1) {
        if (verbose) fprintf(stderr, "channelizer: M too small (%d)\n", M);
        return -1;
    }

    int gidx = c->n_groups++;
    pfb_group_t *grp = &c->groups[gidx];
    memset(grp, 0, sizeof(*grp));
    grp->active = 1;
    grp->bw_hz = bw_hz;
    grp->os_factor = os_factor;
    grp->samp_rate = (double)c->samp_rate;
    double pre_shift = first_channel_hz - (double)c->f_center;
    grp->bin_0_freq = first_channel_hz;
    grp->pfb = pfb_create(M, PFB_TAPS_PER_BR, pre_shift, (double)c->samp_rate);
    if (!grp->pfb) {
        --c->n_groups;
        return -1;
    }
    if (verbose) {
        fprintf(stderr,
                "channelizer: PFB group %d  BW=%d kHz  M=%d  bin0=%.3f MHz  "
                "pre_shift=%+.0f Hz  output=%.3f kHz/bin\n",
                gidx, bw_hz / 1000, M, grp->bin_0_freq / 1e6,
                pre_shift, pfb_output_rate(grp->pfb) / 1e3);
    }
    return gidx;
}

channelizer_t *channelizer_create(uint64_t f_center, uint32_t samp_rate)
{
    channelizer_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->f_center  = f_center;
    c->samp_rate = samp_rate;
    return c;
}

int channelizer_add_channel(channelizer_t *c, const channel_cfg_t *cfg)
{
    if (!c || !cfg) return -1;
    if (c->n_channels >= CHANNELIZER_MAX_CHANNELS) return -1;
    if (cfg->bw_hz <= 0 || c->samp_rate == 0) return -1;
    if ((uint32_t)cfg->bw_hz > c->samp_rate) return -1;

    int os = cfg->os_factor > 0 ? cfg->os_factor : 1;
    /* Critically-sampled PFB outputs at exactly bw_hz, regardless of the
     * caller's requested os_factor. The LoRa demod must be created with
     * os=1 in this mode -- main.c already does that when our channel's
     * BW divides the rate evenly with M >= 2. */
    (void)os;

    int gidx = find_or_create_group(c, cfg->bw_hz, 1, (double)cfg->f_hz);
    if (gidx < 0) return -1;
    pfb_group_t *grp = &c->groups[gidx];
    int M = pfb_M(grp->pfb);

    /* Map channel center frequency to FFT bin index.
     * bin_0_freq corresponds to FFT bin 0 (DC after pre-shift). Channels
     * at bin_0_freq + b*bw_hz for b = -M/2..M/2-1; FFTW's natural order
     * has bin 0 at DC and bin M-1 at -bw_hz from DC, so we mod into
     * [0, M). */
    double offset = (double)cfg->f_hz - grp->bin_0_freq;
    int b_signed = (int)round(offset / (double)cfg->bw_hz);
    int bin = ((b_signed % M) + M) % M;

    /* Sanity: require the channel center to fall inside the SDR RF window.
     * offset above is relative to bin_0_freq for bin assignment, not relative
     * to the SDR center, so do not compare it to +/- samp_rate/2 here. */

    double rf_lo = (double)c->f_center - (double)c->samp_rate * 0.5;
    double rf_hi = (double)c->f_center + (double)c->samp_rate * 0.5;

    if ((double)cfg->f_hz < rf_lo || (double)cfg->f_hz > rf_hi) {
        if (verbose)
            fprintf(stderr, "channelizer: channel %.3f MHz outside Nyquist window\n",
                    (double)cfg->f_hz / 1e6);
        return -1;
    }

    int slot = c->n_channels;
    chan_state_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->id = slot;
    s->cfg = *cfg;
    s->group_idx = gidx;
    s->bin = bin;

    if (pfb_register_bin(grp->pfb, bin, slot, pfb_emit_adapter, s) < 0) {
        free(s);
        return -1;
    }

    /* Publish the slot pointer with release semantics first, then bump
     * the count. SDR thread reads count via __ATOMIC_ACQUIRE and
     * dereferences c->channels[i] for i < count -- the ordering pair
     * keeps it from seeing a NULL pointer post-bump. */
    __atomic_store_n(&c->channels[slot], s, __ATOMIC_RELEASE);
    __atomic_store_n(&c->n_channels, slot + 1, __ATOMIC_RELEASE);

    if (verbose) {
        fprintf(stderr,
                "channelizer ch%-3d: %.3f MHz  bw=%d kHz  group=%d  bin=%d  "
                "SF%d CR4/%d\n",
                slot, (double)cfg->f_hz / 1e6, cfg->bw_hz / 1000, gidx, bin,
                cfg->sf, cfg->cr);
    }
    return slot;
}

int channelizer_num_channels(const channelizer_t *c)
{
    return c ? c->n_channels : 0;
}

void channelizer_process_int8(channelizer_t *c, const int8_t *iq, size_t n)
{
    if (!c || n == 0) return;
    if (c->workbuf_cap < n) {
        float complex *nb = realloc(c->workbuf, sizeof(float complex) * n);
        if (!nb) return;
        c->workbuf = nb;
        c->workbuf_cap = n;
    }
    const float scale = 1.0f / 127.0f;
    for (size_t i = 0; i < n; ++i) {
        c->workbuf[i] = (float)iq[2*i] * scale + I * (float)iq[2*i + 1] * scale;
    }
    /* Run each PFB group in its own thread. Groups have independent
     * state (separate pfb_t instances). */
    int n_groups = c->n_groups;
    float complex *wb = c->workbuf;
#if defined(_OPENMP)
    /* Cap threads to actual parallel work. With ~3 BWs (= 3 PFB groups
     * for Meshtastic), we have 3 independent units; spawning 8+ threads
     * to fight over 3 jobs thrashes the OMP runtime and CPU. */
    #pragma omp parallel for schedule(dynamic, 1) num_threads(n_groups > 0 ? n_groups : 1)
#endif
    for (int g = 0; g < n_groups; ++g) {
        if (c->groups[g].active)
            pfb_process(c->groups[g].pfb, wb, n);
    }
}

void channelizer_process_float(channelizer_t *c, const float complex *iq, size_t n)
{
    if (!c || n == 0) return;
    int n_groups = c->n_groups;
#if defined(_OPENMP)
    /* Cap threads to actual parallel work. With ~3 BWs (= 3 PFB groups
     * for Meshtastic), we have 3 independent units; spawning 8+ threads
     * to fight over 3 jobs thrashes the OMP runtime and CPU. */
    #pragma omp parallel for schedule(dynamic, 1) num_threads(n_groups > 0 ? n_groups : 1)
#endif
    for (int g = 0; g < n_groups; ++g) {
        if (c->groups[g].active)
            pfb_process(c->groups[g].pfb, iq, n);
    }
}

void channelizer_flush(channelizer_t *c)
{
    if (!c) return;
    for (int g = 0; g < c->n_groups; ++g) {
        if (c->groups[g].active)
            pfb_flush(c->groups[g].pfb);
    }
}

void channelizer_destroy(channelizer_t *c)
{
    if (!c) return;
    /* pfb_destroy() drains async sink workers, whose callback user pointers
     * reference chan_state_t. Keep channel state alive until after all PFB
     * sinks have flushed and no worker can call pfb_emit_adapter anymore. */
    for (int g = 0; g < c->n_groups; ++g) {
        if (c->groups[g].pfb) pfb_destroy(c->groups[g].pfb);
    }
    for (int i = 0; i < c->n_channels; ++i) {
        if (c->channels[i]) free(c->channels[i]);
    }
    free(c->workbuf);
    free(c);
}
