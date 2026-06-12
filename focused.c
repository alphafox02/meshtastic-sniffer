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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define FOCUSED_BATCH_SAMPLES   16384
#define FOCUSED_POLL_USEC        2000   /* 2 ms; trades latency for CPU */
#define FOCUSED_LPF_TAPS          257   /* good for os=1; lengthen for os>1 */
#define FOCUSED_PHASOR_RENORM   4096    /* every N samples; |phasor| -> 1 */

struct focused_worker {
    focused_cfg_t cfg;

    /* Mutable slot config + DDC chain. Protected by cfg_mu; the worker
     * thread takes the lock only when it processes a pending slot
     * reconfiguration so the steady-state path is uncontended. */
    pthread_mutex_t cfg_mu;
    double cur_channel_hz;
    int    cur_bw_hz;
    int    cur_sf;
    int    cur_cr;
    int    cur_os_factor;
    int    cur_set;            /* 1 once a slot has been configured */
    /* Pending slot fields written by focused_worker_arm_slot(); the
     * worker thread observes them along with arm_pending and copies
     * into cur_* + rebuilds DDC. */
    double pending_channel_hz;
    int    pending_bw_hz;
    int    pending_sf;
    int    pending_cr;
    int    pending_os_factor;
    int    pending_slot_change;

    /* DDC chain. The mixer runs as a phasor iteration: each input
     * sample multiplies the running phasor by a precomputed
     * per-sample rotation factor instead of recomputing cos/sin from
     * the cumulative phase. That eliminates ~50 ns of libm transcendental
     * work per sample, which was burning ~100% of one CPU core at
     * 20-26 Msps wideband input and causing the worker to fall
     * behind the ring writer. Renormalised every FOCUSED_PHASOR_RENORM
     * samples to prevent magnitude drift from compound float rounding. */
    double mix_inc;
    float complex mix_step;     /* exp(j * mix_inc), precomputed at arm time */
    float complex mix_phasor;   /* running rotation; |mix_phasor| ~ 1 */
    int   phasor_renorm_count;
    float *taps;
    int    n_taps;
    float complex *delay;
    int    delay_head;
    int    decim;
    int    decim_phase;
    double channel_rate;

    /* Decoder. Lifetime is owned by the worker. The trampoline ctx
     * persists across decoder rebuilds so we register-and-forget the
     * same `user` pointer on each new decoder. */
    lora_decoder_t *dec;
    void *frame_trampoline_ctx;

    /* Worker thread + lifecycle */
    pthread_t tid;
    int       started;
    atomic_int run;            /* 1 = thread alive, 0 = drain remainder + exit */
    atomic_int state;          /* focused_state_t */
    int       sticky;          /* 1 = never fall back to IDLE (manual focus) */
    double    hold_down_s;     /* DECODING -> HOLD_DOWN and HOLD_DOWN -> IDLE timer */
    atomic_uint_fast64_t last_frame_mono_us;
    atomic_uint_fast64_t hold_down_start_us;
    uint64_t   start_sample;
    uint64_t   cursor;         /* private to worker thread; reset on arm */
    atomic_int arm_pending;    /* set by focused_worker_arm; cleared by thread */
    char       label_buf[32];

    /* Stats */
    atomic_uint_fast64_t samples_consumed;
    atomic_uint_fast64_t samples_to_decoder;
    atomic_uint_fast64_t frames_delivered;
    atomic_uint_fast64_t samples_skipped;     /* lost to fall-behind */

    /* Fall-behind diagnostics. Classifier per shared next-steps doc:
     * an "edge_start" event is one where the arm-time cursor landed at
     * (or within one batch of) the ring's oldest sample AND we consumed
     * less than one batch before the writer caught us -- i.e. the focus
     * run never really got going. Anything else is a "throughput" event
     * (worker ran for a while, then the math couldn't keep up). */
    atomic_uint_fast64_t fell_behind_total;
    atomic_uint_fast64_t fell_behind_edge_start;
    atomic_uint_fast64_t fell_behind_throughput;
    atomic_uint_fast64_t fell_behind_skipped_max;   /* high-water mark */

    /* Per-arm state captured at the moment we accept an arm. Used by
     * the fall-behind classifier; not visible outside the worker. */
    uint64_t arm_start_sample;
    uint64_t arm_oldest;
    uint64_t arm_newest;
    uint64_t arm_cursor;
    uint64_t arm_mono_us;
    bool     arm_clamped_to_oldest;
    atomic_uint_fast64_t samples_consumed_since_arm;
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

static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

static void focused_frame_trampoline(const uint8_t *payload, size_t len,
                                     const lora_frame_meta_t *meta, void *user)
{
    frame_trampoline_ctx_t *ctx = (frame_trampoline_ctx_t *)user;
    atomic_fetch_add(&ctx->w->frames_delivered, 1);
    /* Refresh activity timer; a frame received during HOLD_DOWN snaps
     * us back into DECODING so a busy slot keeps streaming. */
    uint64_t now = mono_us();
    atomic_store(&ctx->w->last_frame_mono_us, now);
    if (atomic_load(&ctx->w->state) == FOCUSED_STATE_HOLD_DOWN) {
        atomic_store(&ctx->w->state, FOCUSED_STATE_DECODING);
        fprintf(stderr, "focused[%s]: HOLD_DOWN -> DECODING (frame seen)\n",
                ctx->w->label_buf);
    }
    if (ctx->cb) ctx->cb(payload, len, meta, ctx->cb_user);
}

/* Process `n` raw input samples through the DDC. samples is either
 * int8 (2 bytes/IQ pair) or float (8 bytes/IQ pair) depending on the
 * ring's format. chunk_start_sdr_idx is the absolute SDR sample index
 * of the first sample in this batch (= w->cursor before the read);
 * the focused decoder uses it via lora_decoder_set_stream_cursor to
 * stamp a race-free, sample-precise lock anchor on each frame. */
static void focused_process_chunk(focused_worker_t *w,
                                  const void *samples, size_t n,
                                  int format, uint64_t chunk_start_sdr_idx)
{
    const int8_t *si8  = (const int8_t *)samples;
    const float  *sf32 = (const float  *)samples;
    float complex phasor = w->mix_phasor;
    float complex step   = w->mix_step;
    int renorm_count     = w->phasor_renorm_count;
    float complex one_out;
    /* TDOA stream-cursor announce: each consumed channelizer output
     * sample represents w->decim SDR input samples, so the decoder's
     * lock stamp at samples_in_chunk=k corresponds to SDR sample
     * chunk_start_sdr_idx + k*w->decim. Sample-precise for this path
     * because w->cursor is read straight from the IQ ring. */
    if (w->dec) {
        lora_decoder_set_stream_cursor(w->dec, chunk_start_sdr_idx,
                                       (uint32_t)w->decim);
    }
    for (size_t i = 0; i < n; ++i) {
        float ii, qq;
        if (format == SAMPLE_FMT_FLOAT) { ii = sf32[2*i+0]; qq = sf32[2*i+1]; }
        else                            { ii = (float)si8[2*i+0]; qq = (float)si8[2*i+1]; }
        float complex x = ii + I * qq;
        float complex mixed = x * phasor;
        phasor *= step;
        if (++renorm_count >= FOCUSED_PHASOR_RENORM) {
            renorm_count = 0;
            float mag2 = crealf(phasor) * crealf(phasor) +
                         cimagf(phasor) * cimagf(phasor);
            /* sqrt is cheap once per 4096 samples; keep |phasor| at 1
             * so the rotation does not drift in magnitude. */
            phasor = phasor / sqrtf(mag2);
        }
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
    w->mix_phasor = phasor;
    w->phasor_renorm_count = renorm_count;
}

/* Re-build the DDC + decoder for a (possibly new) slot. Called from
 * focused_worker_create() the first time (when w->dec is NULL) and
 * from the worker thread when it sees pending_slot_change. Must be
 * called with w->cfg_mu held -- it mutates the shared cur_* fields
 * and replaces w->dec. Returns 0 on success, -1 on failure (decoder
 * destroy + recreate cycle hit an allocator error). */
static int focused_apply_slot_locked(focused_worker_t *w)
{
    int os    = w->pending_os_factor > 0 ? w->pending_os_factor : w->cfg.os_factor;
    if (!(os == 1 || os == 2 || os == 4 || os == 8)) os = 1;
    double sr = w->cfg.sdr_samp_rate;
    int decim = (int)(sr / (double)(os * w->pending_bw_hz) + 0.5);
    if (decim <= 0) {
        fprintf(stderr, "focused[%s]: rate %.0f not aligned to os*BW=%d\n",
                w->label_buf, sr, os * w->pending_bw_hz);
        return -1;
    }
    w->cur_channel_hz = w->pending_channel_hz;
    w->cur_bw_hz      = w->pending_bw_hz;
    w->cur_sf         = w->pending_sf;
    w->cur_cr         = w->pending_cr;
    w->cur_os_factor  = os;
    w->cur_set        = 1;
    w->mix_inc = -2.0 * M_PI * (w->cur_channel_hz - w->cfg.sdr_center_hz) / sr;
    /* Precompute the single-sample rotation factor; the per-sample
     * loop just multiplies mix_phasor by mix_step. */
    w->mix_step   = (float complex)(cos(w->mix_inc) + I * sin(w->mix_inc));
    w->mix_phasor = 1.0f + 0.0f * I;
    w->phasor_renorm_count = 0;
    w->decim = decim;
    w->decim_phase = 0;
    w->channel_rate = sr / (double)decim;
    /* Reuse the taps + delay buffer (size is fixed by FOCUSED_LPF_TAPS);
     * just rebuild the LPF shape for the new BW. */
    w->n_taps = build_lpf(w->n_taps > 0 ? w->n_taps : FOCUSED_LPF_TAPS,
                          sr, (double)w->cur_bw_hz * 0.5, w->taps);
    memset(w->delay, 0, sizeof(float complex) * (size_t)w->n_taps);
    w->delay_head = 0;
    /* Decoder is bound to (sf, cr, bw, os) at create -- destroy and
     * recreate when any of those change. */
    if (w->dec) lora_decoder_destroy(w->dec);
    w->dec = lora_decoder_create_os(w->cur_sf, w->cur_cr, w->cur_bw_hz, os);
    if (!w->dec) {
        fprintf(stderr, "focused[%s]: lora_decoder_create_os failed for "
                        "sf=%d cr=%d bw=%d os=%d\n",
                w->label_buf, w->cur_sf, w->cur_cr, w->cur_bw_hz, os);
        return -1;
    }
    lora_decoder_set_callback(w->dec, focused_frame_trampoline,
                              w->frame_trampoline_ctx);
    lora_decoder_set_center_freq(w->dec, w->cur_channel_hz);
    return 0;
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

    w->cursor = w->start_sample;
    /* Snap to live range immediately. */
    uint64_t oldest, newest;
    iq_ring_live_range(w->cfg.ring, &oldest, &newest);
    if (w->cursor < oldest) w->cursor = oldest;

    while (atomic_load(&w->run)) {
        /* Honour pending arm requests: re-anchor cursor + refresh
         * activity clock + (possibly) rebuild DDC + flip to DECODING. */
        if (atomic_exchange(&w->arm_pending, 0)) {
            /* Drain a slot reconfiguration too, while we hold cfg_mu.
             * The DDC and decoder are rebuilt in place; existing
             * delay-line / decoder state from a previous slot is
             * discarded so we never produce mixed-slot symbols. */
            pthread_mutex_lock(&w->cfg_mu);
            if (w->pending_slot_change) {
                int rc = focused_apply_slot_locked(w);
                w->pending_slot_change = 0;
                if (rc != 0) {
                    pthread_mutex_unlock(&w->cfg_mu);
                    atomic_store(&w->state, FOCUSED_STATE_IDLE);
                    continue;
                }
                fprintf(stderr,
                        "focused[%s]: slot reconfigured -> ch=%.3fMHz "
                        "BW=%dkHz SF=%d CR=4/%d os=%d\n",
                        w->label_buf, w->cur_channel_hz / 1e6,
                        w->cur_bw_hz / 1000, w->cur_sf, w->cur_cr,
                        w->cur_os_factor);
            }
            pthread_mutex_unlock(&w->cfg_mu);

            uint64_t o2, n2;
            iq_ring_live_range(w->cfg.ring, &o2, &n2);
            bool clamped = false;
            if (w->start_sample == 0 || w->start_sample < o2) {
                w->cursor = o2;
                clamped = true;
            } else if (w->start_sample > n2) {
                w->cursor = n2;
            } else {
                w->cursor = w->start_sample;
            }
            uint64_t now_us = mono_us();
            atomic_store(&w->last_frame_mono_us, now_us);
            atomic_store(&w->state, FOCUSED_STATE_DECODING);

            /* Stash arm-time state for the fall-behind classifier. */
            w->arm_start_sample = w->start_sample;
            w->arm_oldest = o2;
            w->arm_newest = n2;
            w->arm_cursor = w->cursor;
            w->arm_mono_us = now_us;
            w->arm_clamped_to_oldest = clamped;
            atomic_store(&w->samples_consumed_since_arm, 0);

            uint64_t headroom = (w->cursor > o2) ? (w->cursor - o2) : 0;
            double   headroom_ms = (w->cfg.sdr_samp_rate > 0)
                ? (double)headroom * 1000.0 / w->cfg.sdr_samp_rate
                : 0.0;
            fprintf(stderr,
                    "focused[%s]: armed at cursor=%llu  headroom=%llu (%.1fms)%s\n",
                    w->label_buf, (unsigned long long)w->cursor,
                    (unsigned long long)headroom, headroom_ms,
                    clamped ? "  [clamped-to-oldest]" : "");
        }

        focused_state_t st = atomic_load(&w->state);
        if (st == FOCUSED_STATE_IDLE) {
            /* While idle, don't consume samples; just track the writer
             * so an arm() starting from "oldest" lands in the recent
             * window rather than ancient ring history. */
            iq_ring_live_range(w->cfg.ring, &oldest, &newest);
            w->cursor = newest;
            usleep(FOCUSED_POLL_USEC * 4);
            continue;
        }

        /* DECODING or HOLD_DOWN -- both process samples; the only
         * difference is the hysteresis timer below. */
        iq_ring_live_range(w->cfg.ring, &oldest, &newest);
        if (w->cursor < oldest) {
            /* The worker's cursor was overrun by the ring writer:
             * samples between `cursor` and `oldest` are gone. Keeping
             * a partial sample stream after a gap corrupts the
             * decoder's chirp/STO/SFO state and produces nothing,
             * which is exactly what we saw on live B205. Honest
             * answer: drop this focus run, report it, and let the
             * dispatcher arm a fresh attempt next time. */
            uint64_t skipped = oldest - w->cursor;
            atomic_fetch_add(&w->samples_skipped, skipped);

            /* Classifier (per shared next-steps doc):
             *   edge_start  = arm-time cursor was clamped to oldest AND
             *                 we consumed less than one batch before the
             *                 writer caught us (run never got going)
             *   throughput  = anything else (we ran for a while, then
             *                 the math slipped behind line rate)
             * Always uses real per-arm state, not a skip-size heuristic. */
            uint64_t consumed_since_arm =
                atomic_load(&w->samples_consumed_since_arm);
            const char *kind;
            if (w->arm_clamped_to_oldest &&
                consumed_since_arm < FOCUSED_BATCH_SAMPLES) {
                atomic_fetch_add(&w->fell_behind_edge_start, 1);
                kind = "edge_start";
            } else {
                atomic_fetch_add(&w->fell_behind_throughput, 1);
                kind = "throughput";
            }
            atomic_fetch_add(&w->fell_behind_total, 1);

            /* High-water mark for skipped samples. */
            uint64_t prev_max = atomic_load(&w->fell_behind_skipped_max);
            while (skipped > prev_max &&
                   !atomic_compare_exchange_weak(&w->fell_behind_skipped_max,
                                                 &prev_max, skipped)) {
                /* CAS retry */
            }

            uint64_t now_us = mono_us();
            double   age_ms = (double)(now_us - w->arm_mono_us) * 1e-3;
            fprintf(stderr,
                    "focused[%s]: fell behind by %llu samples (~%.1fms) "
                    "kind=%s consumed_since_arm=%llu age=%.0fms; "
                    "dropping focus run and returning to IDLE\n",
                    w->label_buf, (unsigned long long)skipped,
                    (double)skipped * 1000.0 / w->cfg.sdr_samp_rate,
                    kind,
                    (unsigned long long)consumed_since_arm,
                    age_ms);
            w->cursor = newest;
            atomic_store(&w->state, FOCUSED_STATE_IDLE);
            continue;
        }
        if (w->cursor < newest) {
            size_t want = newest - w->cursor;
            if (want > FOCUSED_BATCH_SAMPLES) want = FOCUSED_BATCH_SAMPLES;
            uint64_t chunk_start = w->cursor;
            size_t got = iq_ring_get_window(w->cfg.ring, w->cursor, want, stage);
            if (got > 0) {
                focused_process_chunk(w, stage, got, format, chunk_start);
                atomic_fetch_add(&w->samples_consumed, got);
                atomic_fetch_add(&w->samples_consumed_since_arm, got);
                w->cursor += got;
            }
        } else {
            usleep(FOCUSED_POLL_USEC);
        }

        /* Hysteresis transitions; sticky workers (manual focus) skip
         * them entirely and stay in DECODING for the whole run. */
        if (!w->sticky && w->hold_down_s > 0.0) {
            uint64_t now = mono_us();
            uint64_t last = atomic_load(&w->last_frame_mono_us);
            double idle_s = (double)(now - last) * 1e-6;
            if (st == FOCUSED_STATE_DECODING && idle_s > w->hold_down_s) {
                atomic_store(&w->state, FOCUSED_STATE_HOLD_DOWN);
                atomic_store(&w->hold_down_start_us, now);
                fprintf(stderr, "focused[%s]: DECODING -> HOLD_DOWN "
                                "(%.1fs idle, hd=%.1fs)\n",
                        w->label_buf, idle_s, w->hold_down_s);
            } else if (st == FOCUSED_STATE_HOLD_DOWN) {
                uint64_t hd_start = atomic_load(&w->hold_down_start_us);
                double in_hd_s = (double)(now - hd_start) * 1e-6;
                if (in_hd_s > w->hold_down_s) {
                    atomic_store(&w->state, FOCUSED_STATE_IDLE);
                    fprintf(stderr, "focused[%s]: HOLD_DOWN -> IDLE "
                                    "(%.1fs in hold-down)\n",
                            w->label_buf, in_hd_s);
                }
            }
        }
    }

    /* Final drain whatever remains in the ring between cursor and the
     * writer's final newest_plus_one. Skips when state is IDLE -- a
     * worker that was never armed (or whose hold-down expired before
     * shutdown) has nothing to emit. */
    if (atomic_load(&w->state) != FOCUSED_STATE_IDLE) {
        for (;;) {
            iq_ring_live_range(w->cfg.ring, &oldest, &newest);
            if (w->cursor < oldest) w->cursor = oldest;
            if (w->cursor >= newest) break;
            size_t want = newest - w->cursor;
            if (want > FOCUSED_BATCH_SAMPLES) want = FOCUSED_BATCH_SAMPLES;
            uint64_t chunk_start = w->cursor;
            size_t got = iq_ring_get_window(w->cfg.ring, w->cursor, want, stage);
            if (got == 0) break;
            focused_process_chunk(w, stage, got, format, chunk_start);
            atomic_fetch_add(&w->samples_consumed, got);
            w->cursor += got;
        }
    }

    free(stage);
    return NULL;
}

focused_worker_t *focused_worker_create(const focused_cfg_t *cfg)
{
    if (!cfg || !cfg->ring) return NULL;
    if (cfg->os_factor < 1 || cfg->os_factor > 4) return NULL;

    focused_worker_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cfg = *cfg;
    pthread_mutex_init(&w->cfg_mu, NULL);

    /* Allocate taps + delay at max length once; build_lpf() inside
     * focused_apply_slot_locked() reshapes them per slot. */
    w->n_taps = FOCUSED_LPF_TAPS;
    w->taps   = malloc(sizeof(float) * (size_t)w->n_taps);
    if (!w->taps) { pthread_mutex_destroy(&w->cfg_mu); free(w); return NULL; }
    w->delay  = calloc((size_t)w->n_taps, sizeof(float complex));
    if (!w->delay) {
        free(w->taps); pthread_mutex_destroy(&w->cfg_mu); free(w); return NULL;
    }
    w->delay_head = 0;

    /* Set up the trampoline ctx; survives decoder rebuilds. */
    frame_trampoline_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(w->delay); free(w->taps);
        pthread_mutex_destroy(&w->cfg_mu); free(w);
        return NULL;
    }
    ctx->w = w;
    ctx->cb = cfg->frame_cb;
    ctx->cb_user = cfg->frame_cb_user;
    w->frame_trampoline_ctx = ctx;

    if (cfg->label) {
        snprintf(w->label_buf, sizeof(w->label_buf), "%s", cfg->label);
    } else {
        snprintf(w->label_buf, sizeof(w->label_buf), "focused");
    }

    atomic_init(&w->run, 0);
    atomic_init(&w->state, FOCUSED_STATE_IDLE);
    atomic_init(&w->last_frame_mono_us, 0);
    atomic_init(&w->hold_down_start_us, 0);
    atomic_init(&w->arm_pending, 0);
    atomic_init(&w->samples_consumed, 0);
    atomic_init(&w->samples_to_decoder, 0);
    atomic_init(&w->frames_delivered, 0);
    atomic_init(&w->samples_skipped, 0);
    atomic_init(&w->fell_behind_total, 0);
    atomic_init(&w->fell_behind_edge_start, 0);
    atomic_init(&w->fell_behind_throughput, 0);
    atomic_init(&w->fell_behind_skipped_max, 0);
    atomic_init(&w->samples_consumed_since_arm, 0);
    w->arm_start_sample = 0;
    w->arm_oldest = 0;
    w->arm_newest = 0;
    w->arm_cursor = 0;
    w->arm_mono_us = 0;
    w->arm_clamped_to_oldest = false;
    w->sticky      = 0;
    w->hold_down_s = 0.0;
    w->cursor      = 0;

    /* If cfg specifies an initial slot (legacy single-worker create
     * path used by manual focus and the single auto worker), build
     * the DDC + decoder now so the worker is fully usable from the
     * moment focused_worker_start() returns. Pool-managed workers
     * leave cfg.bw_hz = 0 (and friends) and defer the build to the
     * first focused_worker_arm_slot() call. */
    if (cfg->bw_hz > 0 && cfg->sf >= 7 && cfg->sf <= 12 &&
        cfg->cr >= 5 && cfg->cr <= 8 && cfg->channel_hz > 0.0) {
        pthread_mutex_lock(&w->cfg_mu);
        w->pending_channel_hz = cfg->channel_hz;
        w->pending_bw_hz      = cfg->bw_hz;
        w->pending_sf         = cfg->sf;
        w->pending_cr         = cfg->cr;
        w->pending_os_factor  = cfg->os_factor;
        int rc = focused_apply_slot_locked(w);
        pthread_mutex_unlock(&w->cfg_mu);
        if (rc != 0) {
            free(ctx); free(w->delay); free(w->taps);
            pthread_mutex_destroy(&w->cfg_mu); free(w);
            return NULL;
        }
        fprintf(stderr,
                "focused[%s]: ch=%.3fMHz BW=%dkHz SF=%d CR=4/%d os=%d  "
                "decim=%d -> %.0f sps  ntaps=%d\n",
                w->label_buf, cfg->channel_hz / 1e6, cfg->bw_hz / 1000,
                cfg->sf, cfg->cr, cfg->os_factor, w->decim,
                w->channel_rate, w->n_taps);
    } else {
        fprintf(stderr,
                "focused[%s]: created in generic mode (os=%d, slot deferred "
                "until first arm_slot)\n",
                w->label_buf, cfg->os_factor);
    }
    return w;
}

int focused_worker_start(focused_worker_t *w, uint64_t start_sample,
                         int sticky_arm)
{
    if (!w || w->started) return -1;
    w->start_sample = start_sample;
    w->sticky       = sticky_arm ? 1 : 0;
    if (sticky_arm) {
        /* Manual focus: immediately enter DECODING and never leave.
         * The thread sees state != IDLE and processes from start_sample. */
        atomic_store(&w->state, FOCUSED_STATE_DECODING);
        atomic_store(&w->last_frame_mono_us, mono_us());
    } else {
        atomic_store(&w->state, FOCUSED_STATE_IDLE);
    }
    atomic_store(&w->run, 1);
    if (pthread_create(&w->tid, NULL, focused_thread, w) != 0) {
        atomic_store(&w->run, 0);
        return -1;
    }
    w->started = 1;
    return 0;
}

void focused_worker_arm(focused_worker_t *w,
                        uint64_t start_sample,
                        double hold_down_s)
{
    if (!w) return;
    w->start_sample = start_sample;
    w->hold_down_s  = hold_down_s > 0.0 ? hold_down_s : 5.0;
    atomic_store(&w->last_frame_mono_us, mono_us());
    /* Flip state to DECODING synchronously so the pool dispatcher's
     * "find an IDLE worker" loop sees this worker as busy on the
     * very next preamble-lock callback. Without this, two locks
     * arriving within ~2 ms (the worker poll interval) could both
     * pick the same worker because arm_pending alone doesn't change
     * what the dispatcher reads. The worker thread still observes
     * arm_pending and (re)builds DDC / cursor / activity timer
     * inside its loop. */
    atomic_store(&w->state, FOCUSED_STATE_DECODING);
    atomic_store(&w->arm_pending, 1);
}

void focused_worker_arm_slot(focused_worker_t *w,
                             double channel_hz, int bw_hz,
                             int sf, int cr,
                             uint64_t start_sample,
                             double hold_down_s)
{
    focused_worker_arm_slot_os(w, channel_hz, bw_hz, sf, cr, 0,
                               start_sample, hold_down_s);
}

void focused_worker_arm_slot_os(focused_worker_t *w,
                                double channel_hz, int bw_hz,
                                int sf, int cr, int os_factor,
                                uint64_t start_sample,
                                double hold_down_s)
{
    if (!w) return;
    pthread_mutex_lock(&w->cfg_mu);
    /* Fill defaults from current slot when caller passes 0 to keep a
     * field. cur_set==0 means this is the worker's first arm; allow
     * channel_hz=0 only if the caller really did mean the previous
     * slot (which doesn't exist) -- treat as error. */
    double next_ch = (channel_hz > 0.0) ? channel_hz : w->cur_channel_hz;
    int    next_bw = (bw_hz      >  0 ) ? bw_hz      : w->cur_bw_hz;
    int    next_sf = (sf         >  0 ) ? sf         : w->cur_sf;
    int    next_cr = (cr         >  0 ) ? cr         : w->cur_cr;
    int    next_os = (os_factor  >  0 ) ? os_factor  : (w->cur_set ? w->cur_os_factor
                                                                    : w->cfg.os_factor);
    int slot_changed = !w->cur_set ||
                       next_ch != w->cur_channel_hz ||
                       next_bw != w->cur_bw_hz ||
                       next_sf != w->cur_sf ||
                       next_cr != w->cur_cr ||
                       next_os != w->cur_os_factor;
    if (slot_changed) {
        w->pending_channel_hz = next_ch;
        w->pending_bw_hz      = next_bw;
        w->pending_sf         = next_sf;
        w->pending_cr         = next_cr;
        w->pending_os_factor  = next_os;
        w->pending_slot_change = 1;
    }
    pthread_mutex_unlock(&w->cfg_mu);
    focused_worker_arm(w, start_sample, hold_down_s);
}

int focused_worker_current_slot(const focused_worker_t *w,
                                double *freq_hz_out, int *bw_hz_out,
                                int *sf_out, int *cr_out)
{
    if (!w) return 0;
    focused_worker_t *rw = (focused_worker_t *)w;
    pthread_mutex_lock(&rw->cfg_mu);
    int has = w->cur_set;
    if (freq_hz_out) *freq_hz_out = w->cur_channel_hz;
    if (bw_hz_out)   *bw_hz_out   = w->cur_bw_hz;
    if (sf_out)      *sf_out      = w->cur_sf;
    if (cr_out)      *cr_out      = w->cur_cr;
    pthread_mutex_unlock(&rw->cfg_mu);
    return has;
}

focused_state_t focused_worker_state(const focused_worker_t *w)
{
    return w ? (focused_state_t)atomic_load(&((focused_worker_t *)w)->state)
             : FOCUSED_STATE_IDLE;
}

void focused_worker_stop_and_join(focused_worker_t *w)
{
    if (!w || !w->started) return;
    atomic_store(&w->run, 0);
    pthread_join(w->tid, NULL);
    w->started = 0;
    fprintf(stderr,
            "focused[%s]: consumed=%llu decoded=%llu frames=%llu skipped=%llu "
            "fell_behind=%llu (edge_start=%llu throughput=%llu) "
            "skip_max=%llu samples\n",
            w->label_buf,
            (unsigned long long)atomic_load(&w->samples_consumed),
            (unsigned long long)atomic_load(&w->samples_to_decoder),
            (unsigned long long)atomic_load(&w->frames_delivered),
            (unsigned long long)atomic_load(&w->samples_skipped),
            (unsigned long long)atomic_load(&w->fell_behind_total),
            (unsigned long long)atomic_load(&w->fell_behind_edge_start),
            (unsigned long long)atomic_load(&w->fell_behind_throughput),
            (unsigned long long)atomic_load(&w->fell_behind_skipped_max));
}

void focused_worker_destroy(focused_worker_t *w)
{
    if (!w) return;
    if (w->dec) lora_decoder_destroy(w->dec);
    free(w->frame_trampoline_ctx);
    free(w->delay);
    free(w->taps);
    pthread_mutex_destroy(&w->cfg_mu);
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

uint64_t focused_worker_fell_behind_total(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->fell_behind_total) : 0;
}

uint64_t focused_worker_fell_behind_edge_start(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->fell_behind_edge_start) : 0;
}

uint64_t focused_worker_fell_behind_throughput(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->fell_behind_throughput) : 0;
}

uint64_t focused_worker_fell_behind_skipped_max(const focused_worker_t *w)
{
    return w ? atomic_load(&((focused_worker_t *)w)->fell_behind_skipped_max) : 0;
}
