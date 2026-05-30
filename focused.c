/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * focused -- raw-IQ-fed single-slot focused decoder. See focused.h.
 *
 * DDC math (NCO mixer, Hamming LPF, decimator) is the same shape as
 * tests/focused_demo.c / tests/test_oversample_self.c so a focused
 * worker driven from the live ring decodes bit-identical to the
 * proven file-replay path. The worker thread pulls samples from the
 * ring in fixed batches, copies them into a private cs8 or cf32
 * staging buffer (so the ring's mutex isn't held during DDC), and
 * feeds decimated complex samples into lora_decoder_feed().
 */

#include "focused.h"
#include "sdr.h"

#include <complex.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define FOCUSED_BATCH_SAMPLES   16384
#define FOCUSED_POLL_USEC        2000   /* 2 ms; trades latency for CPU */
#define FOCUSED_LPF_TAPS          257   /* good for os=1; lengthen for os>1 */

struct focused_worker {
    focused_cfg_t cfg;

    /* DDC chain */
    double mix_inc;
    double mix_phase;
    float *taps;
    int    n_taps;
    float complex *delay;
    int    delay_head;
    int    decim;
    int    decim_phase;
    double channel_rate;

    /* Decoder */
    lora_decoder_t *dec;

    /* Worker thread + lifecycle */
    pthread_t tid;
    int       started;
    atomic_int run;            /* 1 = pull more samples, 0 = drain remainder + exit */
    uint64_t   start_sample;
    char       label_buf[32];

    /* Stats */
    atomic_uint_fast64_t samples_consumed;
    atomic_uint_fast64_t samples_to_decoder;
    atomic_uint_fast64_t frames_delivered;
};

/* Hamming-windowed sinc LPF, cutoff at BW/2. Same shape as
 * tests/focused_demo.c and tests/test_oversample_self.c. */
static int build_lpf(int n_taps, double samp_rate, double cutoff_hz,
                     float *taps)
{
    if (n_taps < 21) n_taps = 21;
    if ((n_taps & 1) == 0) n_taps += 1;
    int c = n_taps / 2;
    double fc = cutoff_hz / samp_rate;
    double sum = 0.0;
    for (int i = 0; i < n_taps; ++i) {
        int n = i - c;
        double s = (n == 0)
                   ? 2.0 * fc
                   : sin(2.0 * M_PI * fc * n) / (M_PI * n);
        double w = 0.54 - 0.46 * cos(2.0 * M_PI * i / (n_taps - 1));
        taps[i] = (float)(s * w);
        sum += taps[i];
    }
    if (sum > 0.0) for (int i = 0; i < n_taps; ++i) taps[i] = (float)(taps[i] / sum);
    return n_taps;
}

/* Wraps the user-supplied frame callback so we can keep our own
 * stat. The user pointer reaching the wideband on_lora_frame is the
 * channel_id the focused worker was registered under, NOT the
 * focused_worker_t -- that way dedup / feed / web all behave the
 * same as for any other channel. */
typedef struct {
    focused_worker_t *w;
    lora_frame_cb_t   cb;
    void             *cb_user;
} frame_trampoline_ctx_t;

static void focused_frame_trampoline(const uint8_t *payload, size_t len,
                                     const lora_frame_meta_t *meta, void *user)
{
    frame_trampoline_ctx_t *ctx = (frame_trampoline_ctx_t *)user;
    atomic_fetch_add(&ctx->w->frames_delivered, 1);
    if (ctx->cb) ctx->cb(payload, len, meta, ctx->cb_user);
}

/* Process `n` raw input samples through the DDC. samples is either
 * int8 (2 bytes/IQ pair) or float (8 bytes/IQ pair) depending on the
 * ring's format. */
static void focused_process_chunk(focused_worker_t *w,
                                  const void *samples, size_t n,
                                  int format)
{
    const int8_t *si8  = (const int8_t *)samples;
    const float  *sf32 = (const float  *)samples;
    float complex one_out;
    for (size_t i = 0; i < n; ++i) {
        float ii, qq;
        if (format == SAMPLE_FMT_FLOAT) { ii = sf32[2*i+0]; qq = sf32[2*i+1]; }
        else                            { ii = (float)si8[2*i+0]; qq = (float)si8[2*i+1]; }
        float complex x = ii + I * qq;
        float complex rot = (float complex)(cos(w->mix_phase) + I * sin(w->mix_phase));
        float complex mixed = x * rot;
        w->mix_phase += w->mix_inc;
        if (w->mix_phase >  M_PI) w->mix_phase -= 2.0 * M_PI;
        if (w->mix_phase < -M_PI) w->mix_phase += 2.0 * M_PI;
        w->delay[w->delay_head] = mixed;
        w->delay_head = (w->delay_head + 1) % w->n_taps;
        if (++w->decim_phase >= w->decim) {
            w->decim_phase = 0;
            float complex acc = 0.0f + 0.0f * I;
            int idx = w->delay_head;
            for (int t = 0; t < w->n_taps; ++t) {
                acc += w->delay[idx] * w->taps[t];
                idx = (idx + 1) % w->n_taps;
            }
            one_out = acc;
            lora_decoder_feed(w->dec, &one_out, 1);
            atomic_fetch_add(&w->samples_to_decoder, 1);
        }
    }
}

static void *focused_thread(void *arg)
{
    focused_worker_t *w = arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), w->label_buf[0] ? w->label_buf : "focused");
#endif
    int    format = iq_ring_format(w->cfg.ring);
    size_t bps    = iq_ring_bytes_per_sample(format);
    void  *stage  = malloc(FOCUSED_BATCH_SAMPLES * bps);
    if (!stage) {
        fprintf(stderr, "focused[%s]: staging alloc failed\n",
                w->label_buf[0] ? w->label_buf : "?");
        return NULL;
    }

    uint64_t cursor = w->start_sample;
    /* Snap to live range immediately. */
    uint64_t oldest, newest;
    iq_ring_live_range(w->cfg.ring, &oldest, &newest);
    if (cursor < oldest) cursor = oldest;

    while (atomic_load(&w->run)) {
        iq_ring_live_range(w->cfg.ring, &oldest, &newest);
        if (cursor < oldest) {
            /* Fell behind the live window -- jump forward, log once. */
            fprintf(stderr, "focused[%s]: cursor advanced %llu -> %llu (fell behind)\n",
                    w->label_buf, (unsigned long long)cursor,
                    (unsigned long long)oldest);
            cursor = oldest;
        }
        if (cursor >= newest) {
            usleep(FOCUSED_POLL_USEC);
            continue;
        }
        size_t want = newest - cursor;
        if (want > FOCUSED_BATCH_SAMPLES) want = FOCUSED_BATCH_SAMPLES;
        size_t got = iq_ring_get_window(w->cfg.ring, cursor, want, stage);
        if (got == 0) { usleep(FOCUSED_POLL_USEC); continue; }
        focused_process_chunk(w, stage, got, format);
        atomic_fetch_add(&w->samples_consumed, got);
        cursor += got;
    }

    /* Drain whatever remains in the ring between cursor and the writer's
     * final newest_plus_one. */
    for (;;) {
        iq_ring_live_range(w->cfg.ring, &oldest, &newest);
        if (cursor < oldest) cursor = oldest;
        if (cursor >= newest) break;
        size_t want = newest - cursor;
        if (want > FOCUSED_BATCH_SAMPLES) want = FOCUSED_BATCH_SAMPLES;
        size_t got = iq_ring_get_window(w->cfg.ring, cursor, want, stage);
        if (got == 0) break;
        focused_process_chunk(w, stage, got, format);
        atomic_fetch_add(&w->samples_consumed, got);
        cursor += got;
    }

    free(stage);
    return NULL;
}

focused_worker_t *focused_worker_create(const focused_cfg_t *cfg)
{
    if (!cfg || !cfg->ring) return NULL;
    if (cfg->os_factor < 1 || cfg->os_factor > 4) return NULL;
    if (cfg->sf < 7 || cfg->sf > 12) return NULL;
    if (cfg->cr < 5 || cfg->cr > 8)  return NULL;
    if (cfg->bw_hz <= 0)             return NULL;

    int os = cfg->os_factor;
    int decim = (int)(cfg->sdr_samp_rate / (double)(os * cfg->bw_hz) + 0.5);
    if (decim <= 0) {
        fprintf(stderr, "focused: rate %.0f not divisible by os*BW=%d\n",
                cfg->sdr_samp_rate, os * cfg->bw_hz);
        return NULL;
    }

    focused_worker_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cfg = *cfg;

    w->mix_inc   = -2.0 * M_PI * (cfg->channel_hz - cfg->sdr_center_hz)
                                 / cfg->sdr_samp_rate;
    w->mix_phase = 0.0;
    w->decim     = decim;
    w->channel_rate = cfg->sdr_samp_rate / (double)decim;
    w->decim_phase  = 0;
    w->n_taps = FOCUSED_LPF_TAPS;
    w->taps   = malloc(sizeof(float) * (size_t)w->n_taps);
    if (!w->taps) { free(w); return NULL; }
    w->n_taps = build_lpf(w->n_taps, cfg->sdr_samp_rate,
                          (double)cfg->bw_hz * 0.5, w->taps);
    w->delay  = calloc((size_t)w->n_taps, sizeof(float complex));
    if (!w->delay) { free(w->taps); free(w); return NULL; }
    w->delay_head = 0;
    w->dec = lora_decoder_create_os(cfg->sf, cfg->cr, cfg->bw_hz, os);
    if (!w->dec) { free(w->delay); free(w->taps); free(w); return NULL; }

    /* Set up the trampoline. We allocate ctx alongside the worker so its
     * lifetime matches the worker; lora_decoder_set_callback holds the
     * pointer. */
    frame_trampoline_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        lora_decoder_destroy(w->dec); free(w->delay); free(w->taps); free(w);
        return NULL;
    }
    ctx->w = w;
    ctx->cb = cfg->frame_cb;
    ctx->cb_user = cfg->frame_cb_user;
    lora_decoder_set_callback(w->dec, focused_frame_trampoline, ctx);
    lora_decoder_set_center_freq(w->dec, cfg->channel_hz);

    if (cfg->label) {
        snprintf(w->label_buf, sizeof(w->label_buf), "%s", cfg->label);
    } else {
        snprintf(w->label_buf, sizeof(w->label_buf), "focused");
    }

    atomic_init(&w->run, 0);
    atomic_init(&w->samples_consumed, 0);
    atomic_init(&w->samples_to_decoder, 0);
    atomic_init(&w->frames_delivered, 0);

    fprintf(stderr,
            "focused[%s]: ch=%.3fMHz BW=%dkHz SF=%d CR=4/%d os=%d  "
            "decim=%d -> %.0f sps  ntaps=%d\n",
            w->label_buf, cfg->channel_hz / 1e6, cfg->bw_hz / 1000,
            cfg->sf, cfg->cr, os, decim, w->channel_rate, w->n_taps);
    return w;
}

int focused_worker_start(focused_worker_t *w, uint64_t start_sample)
{
    if (!w || w->started) return -1;
    w->start_sample = start_sample;
    atomic_store(&w->run, 1);
    if (pthread_create(&w->tid, NULL, focused_thread, w) != 0) {
        atomic_store(&w->run, 0);
        return -1;
    }
    w->started = 1;
    return 0;
}

void focused_worker_stop_and_join(focused_worker_t *w)
{
    if (!w || !w->started) return;
    atomic_store(&w->run, 0);
    pthread_join(w->tid, NULL);
    w->started = 0;
    fprintf(stderr,
            "focused[%s]: consumed=%llu decoded=%llu frames=%llu\n",
            w->label_buf,
            (unsigned long long)atomic_load(&w->samples_consumed),
            (unsigned long long)atomic_load(&w->samples_to_decoder),
            (unsigned long long)atomic_load(&w->frames_delivered));
}

void focused_worker_destroy(focused_worker_t *w)
{
    if (!w) return;
    /* Trampoline ctx leak intentional here -- a worker is created once
     * for the program lifetime in Commit 2; the OS reclaims it on exit.
     * Commit 3 introduces a real lifecycle that frees it. */
    if (w->dec) lora_decoder_destroy(w->dec);
    free(w->delay);
    free(w->taps);
    free(w);
}

uint64_t focused_worker_samples_consumed(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->samples_consumed) : 0;
}

uint64_t focused_worker_samples_to_decoder(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->samples_to_decoder) : 0;
}

uint64_t focused_worker_frames_delivered(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->frames_delivered) : 0;
}
