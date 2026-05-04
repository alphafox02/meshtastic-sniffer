/*
 * meshtastic-sniffer: per-channel decimating DDC.
 *
 * For each configured channel we run:
 *   1. Complex NCO mixer (rotates channel center to DC)
 *   2. Decimating FIR LPF (Hamming-windowed sinc, cutoff = bw_hz/2)
 *   3. Batched callback into the LoRa demod
 *
 * Decimation factor = samp_rate / bw_hz (must be integer). At 20 Msps
 * with BW=250 kHz, decim = 80.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "channelizer.h"
#include "options.h"

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *aligned64(size_t bytes)
{
    void *p = NULL;
    if (posix_memalign(&p, 64, bytes) != 0) return NULL;
    return p;
}

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define DEFAULT_NTAPS 63

typedef struct chan_state {
    int               id;
    channel_cfg_t     cfg;

    double            nco_phase;       /* radians */
    double            nco_phase_inc;   /* radians/sample at samp_rate */

    int               decim;           /* samp_rate / bw_hz */
    int               ntaps;
    float            *taps;            /* real-valued LPF taps, ntaps long */
    float complex    *delay;           /* circular delay line, ntaps long */
    int               delay_idx;       /* next-write index in delay line */
    int               decim_count;     /* 0..decim-1 */

    float complex     outbuf[CHANNELIZER_OUTBUF_SAMPLES];
    int               outbuf_count;
} chan_state_t;

struct channelizer {
    uint64_t      f_center;
    uint32_t      samp_rate;
    int           n_channels;
    chan_state_t *channels[CHANNELIZER_MAX_CHANNELS];
};

/* Hamming-windowed sinc, real-valued LPF, normalized DC gain = 1. */
static void design_lpf(float *taps, int ntaps, double cutoff_norm)
{
    /* cutoff_norm = cutoff_hz / fs (the rate the FIR runs at) */
    double sum = 0.0;
    int M = ntaps - 1;
    for (int n = 0; n < ntaps; ++n) {
        double k = n - M / 2.0;
        double sinc = (k == 0.0)
            ? 2.0 * cutoff_norm
            : sin(2.0 * M_PI * cutoff_norm * k) / (M_PI * k);
        double w = 0.54 - 0.46 * cos(2.0 * M_PI * (double)n / (double)M);
        taps[n] = (float)(sinc * w);
        sum += taps[n];
    }
    if (sum > 0.0) {
        for (int n = 0; n < ntaps; ++n)
            taps[n] = (float)(taps[n] / sum);
    }
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
    if (!c || !cfg || c->n_channels >= CHANNELIZER_MAX_CHANNELS)
        return -1;

    if (cfg->bw_hz <= 0 || c->samp_rate == 0)
        return -1;
    if ((uint32_t)cfg->bw_hz > c->samp_rate)
        return -1;
    if (c->samp_rate % (uint32_t)cfg->bw_hz != 0) {
        if (verbose)
            fprintf(stderr, "channelizer: non-integer decimation: rate=%u bw=%d\n",
                    c->samp_rate, cfg->bw_hz);
        return -1;
    }

    chan_state_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;

    s->id    = c->n_channels;
    s->cfg   = *cfg;
    s->decim = (int)(c->samp_rate / (uint32_t)cfg->bw_hz);
    s->ntaps = DEFAULT_NTAPS;

    s->taps  = aligned64(sizeof(float) * (size_t)s->ntaps);
    s->delay = aligned64(sizeof(float complex) * (size_t)s->ntaps);
    if (!s->taps || !s->delay) {
        free(s->taps); free(s->delay); free(s);
        return -1;
    }

    /* LPF cutoff at fs (samp_rate-domain) = bw_hz / 2. Normalised: bw/(2*fs). */
    double cutoff_norm = (double)cfg->bw_hz / (2.0 * (double)c->samp_rate);
    design_lpf(s->taps, s->ntaps, cutoff_norm);
    memset(s->delay, 0, sizeof(float complex) * (size_t)s->ntaps);

    /* NCO rotates channel center to DC.  Note negative sign: we want to
     * mix down by f_offset, so multiply input by exp(-j 2 pi f_off t). */
    double f_off = (double)((int64_t)cfg->f_hz - (int64_t)c->f_center);
    s->nco_phase     = 0.0;
    s->nco_phase_inc = -2.0 * M_PI * f_off / (double)c->samp_rate;

    /* Publish atomically so the SDR thread can observe the new
     * channels[id] pointer before it sees the bumped n_channels.
     * Release-store pairs with the acquire-load in process_*. */
    int new_id = c->n_channels;
    c->channels[new_id] = s;
    __atomic_store_n(&c->n_channels, new_id + 1, __ATOMIC_RELEASE);

    if (verbose) {
        fprintf(stderr,
                "channelizer ch%-3d: %.3f MHz (%+.3f MHz from center), "
                "BW %d kHz, SF%d, CR4/%d, decim=%d\n",
                s->id, cfg->f_hz / 1e6, f_off / 1e6,
                cfg->bw_hz / 1000, cfg->sf, cfg->cr, s->decim);
    }
    return s->id;
}

int channelizer_num_channels(const channelizer_t *c)
{
    return c ? c->n_channels : 0;
}

/* Process one wideband sample for one channel:
 *  - mix down via NCO rotation
 *  - push into delay line
 *  - on every decim-th input, evaluate FIR and emit one output */
static inline void chan_step(chan_state_t *s, float complex x)
{
    /* NCO rotate */
    float complex rot = (float complex)(cos(s->nco_phase) + I * sin(s->nco_phase));
    s->nco_phase += s->nco_phase_inc;
    /* keep phase in a sane range */
    if (s->nco_phase >  100.0 * 2.0 * M_PI) s->nco_phase -= 100.0 * 2.0 * M_PI;
    if (s->nco_phase < -100.0 * 2.0 * M_PI) s->nco_phase += 100.0 * 2.0 * M_PI;

    float complex y = x * rot;

    /* push into circular delay line */
    s->delay[s->delay_idx] = y;
    s->delay_idx = (s->delay_idx + 1) % s->ntaps;

    if (++s->decim_count < s->decim)
        return;
    s->decim_count = 0;

    /* FIR: y = sum_{k=0..ntaps-1} taps[k] * delay[(idx-1-k) mod N] */
    float complex acc = 0.0f + 0.0f * I;
    int idx = s->delay_idx - 1;
    if (idx < 0) idx += s->ntaps;
    for (int k = 0; k < s->ntaps; ++k) {
        acc += s->taps[k] * s->delay[idx];
        idx = idx ? idx - 1 : s->ntaps - 1;
    }

    s->outbuf[s->outbuf_count++] = acc;
    if (s->outbuf_count == CHANNELIZER_OUTBUF_SAMPLES) {
        if (s->cfg.on_baseband)
            s->cfg.on_baseband(s->id, s->outbuf, (size_t)s->outbuf_count, s->cfg.user);
        s->outbuf_count = 0;
    }
}

void channelizer_process_int8(channelizer_t *c, const int8_t *iq_pairs, size_t n_complex)
{
    if (!c) return;
    const float scale = 1.0f / 127.0f;
    int n_ch = __atomic_load_n(&c->n_channels, __ATOMIC_ACQUIRE);
    for (size_t i = 0; i < n_complex; ++i) {
        float complex x = (float)iq_pairs[2*i] * scale
                        + I * (float)iq_pairs[2*i + 1] * scale;
        for (int ch = 0; ch < n_ch; ++ch)
            chan_step(c->channels[ch], x);
    }
}

void channelizer_process_float(channelizer_t *c, const float complex *iq, size_t n_complex)
{
    if (!c) return;
    int n_ch = __atomic_load_n(&c->n_channels, __ATOMIC_ACQUIRE);
    for (size_t i = 0; i < n_complex; ++i) {
        for (int ch = 0; ch < n_ch; ++ch)
            chan_step(c->channels[ch], iq[i]);
    }
}

void channelizer_flush(channelizer_t *c)
{
    if (!c) return;
    int n_ch = __atomic_load_n(&c->n_channels, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n_ch; ++i) {
        chan_state_t *s = c->channels[i];
        if (!s || s->outbuf_count == 0) continue;
        if (s->cfg.on_baseband)
            s->cfg.on_baseband(s->id, s->outbuf, (size_t)s->outbuf_count, s->cfg.user);
        s->outbuf_count = 0;
    }
}

void channelizer_destroy(channelizer_t *c)
{
    if (!c) return;
    for (int i = 0; i < c->n_channels; ++i) {
        if (c->channels[i]) {
            free(c->channels[i]->taps);
            free(c->channels[i]->delay);
            free(c->channels[i]);
        }
    }
    free(c);
}
