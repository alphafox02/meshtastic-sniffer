/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * focused -- a single LoRa-slot focused decoder driven by samples
 * pulled from the raw-IQ ring buffer (iq_ring.h). Each worker owns
 * one DDC chain (NCO mixer + Hamming LPF + decimator) and one
 * lora_decoder_t. The worker runs on its own thread, polls the ring
 * at a fixed batch size, and emits frames through the supplied
 * lora_frame_cb_t so the same dedup / feed / JSON pipeline carries
 * them. Slot config (channel_hz / bw / sf / cr) can be set at create
 * time (manual focus) or deferred until the first arm_slot() call
 * (pool-managed workers).
 */

#ifndef FOCUSED_H
#define FOCUSED_H

#include "iq_ring.h"
#include "lora.h"

#include <stdint.h>
#include <stddef.h>

typedef struct focused_worker focused_worker_t;

/* Lifecycle state. The worker drives the DECODING -> HOLD_DOWN ->
 * IDLE transitions internally based on hold_down_s; external code
 * (the scan-then-focus pool dispatcher) drives IDLE -> DECODING via
 * focused_worker_arm() / focused_worker_arm_slot(). */
typedef enum {
    FOCUSED_STATE_IDLE       = 0,
    FOCUSED_STATE_DECODING   = 1,
    FOCUSED_STATE_HOLD_DOWN  = 2,
} focused_state_t;

typedef struct {
    /* Channel under focus. */
    double channel_hz;
    int    bw_hz;
    int    sf;
    int    cr;
    int    os_factor;        /* default 1; >1 reserved for next side-task */

    /* Reference frame: SDR center + capture sample rate. Used to
     * compute the mixer increment and the input->output decimation. */
    double sdr_center_hz;
    double sdr_samp_rate;

    /* Where to pull raw IQ from. The worker does not own the ring. */
    iq_ring_t *ring;

    /* on_lora_frame callback + user (channel_id) so the focused path
     * funnels into the same dedup / feed / JSON / web pipeline the
     * wideband channels already use. */
    lora_frame_cb_t frame_cb;
    void           *frame_cb_user;

    /* Optional human label for logging ("focus#0" etc). */
    const char *label;
} focused_cfg_t;

/* Create a worker, configure its DDC chain and decoder. Does not start
 * a thread -- call focused_worker_start() to begin pulling samples. */
focused_worker_t *focused_worker_create(const focused_cfg_t *cfg);
void              focused_worker_destroy(focused_worker_t *w);

/* Start the worker thread. After start the worker sits in IDLE and
 * does not consume samples until armed. Pass `sticky_arm=1` to
 * immediately arm the worker permanently (manual focus mode, won't
 * fall back to IDLE on inactivity); `sticky_arm=0` leaves it idle for
 * a later focused_worker_arm() call. start_sample is the absolute
 * sample index from which the worker resumes once armed; if older
 * than the live range it is silently snapped forward. */
int  focused_worker_start(focused_worker_t *w, uint64_t start_sample,
                          int sticky_arm);

/* Arm the worker (IDLE -> DECODING) for a single activity window.
 * hold_down_s is the hysteresis: after that many seconds elapse with
 * no decoded frame the worker transitions DECODING -> HOLD_DOWN, then
 * after another hold_down_s with still no frame, HOLD_DOWN -> IDLE.
 * A frame delivered during HOLD_DOWN snaps the worker back to
 * DECODING. start_sample identifies where in the ring to begin DDC
 * (set to 0 to mean "oldest live"). Safe to call from any thread. */
void focused_worker_arm(focused_worker_t *w,
                        uint64_t start_sample,
                        double hold_down_s);

/* Same as focused_worker_arm() but additionally reconfigures the
 * worker's DDC chain for a (possibly different) channel slot. Used
 * by the pool dispatcher when a single worker floats between slots
 * over its lifetime. Passing any of
 * channel_hz/bw_hz/sf/cr as 0 keeps the current value for that
 * field. If the resulting slot exactly matches the worker's current
 * config, no DDC rebuild happens -- just an arm() refresh. */
void focused_worker_arm_slot(focused_worker_t *w,
                             double channel_hz, int bw_hz,
                             int sf, int cr,
                             uint64_t start_sample,
                             double hold_down_s);

/* Same as focused_worker_arm_slot(), but the caller may override the
 * worker's decoder oversampling for this slot. Pass os_factor=0 to keep
 * the worker default. */
void focused_worker_arm_slot_os(focused_worker_t *w,
                                double channel_hz, int bw_hz,
                                int sf, int cr, int os_factor,
                                uint64_t start_sample,
                                double hold_down_s);

/* Read back the slot the worker is currently configured for. Returns
 * 1 if a slot is set (worker has been armed at least once), 0
 * otherwise. Output pointers are optional. Safe to call from any
 * thread. */
int  focused_worker_current_slot(const focused_worker_t *w,
                                 double *freq_hz_out, int *bw_hz_out,
                                 int *sf_out, int *cr_out);

focused_state_t focused_worker_state(const focused_worker_t *w);

/* Ask the worker to stop after it drains everything currently in the
 * ring. Blocks until the worker thread joins. */
void focused_worker_stop_and_join(focused_worker_t *w);

/* Stats, mostly for stderr at shutdown. */
uint64_t focused_worker_samples_consumed(const focused_worker_t *w);
uint64_t focused_worker_samples_to_decoder(const focused_worker_t *w);
uint64_t focused_worker_frames_delivered(const focused_worker_t *w);

/* Fall-behind diagnostic counters. Read-only snapshots; safe to call
 * while the worker thread is running. */
uint64_t focused_worker_fell_behind_total(const focused_worker_t *w);
uint64_t focused_worker_fell_behind_edge_start(const focused_worker_t *w);
uint64_t focused_worker_fell_behind_throughput(const focused_worker_t *w);
uint64_t focused_worker_fell_behind_skipped_max(const focused_worker_t *w);

#endif
