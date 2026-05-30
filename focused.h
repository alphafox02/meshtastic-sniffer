/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * focused -- a single LoRa-slot focused decoder driven by samples
 * pulled from the raw-IQ ring buffer (iq_ring.h). Each worker owns
 * one DDC chain (NCO mixer + Hamming LPF + decimator) and one
 * lora_decoder_t configured for a specific (SF, CR, BW) tuple. The
 * worker runs on its own thread, polling the ring at a fixed batch
 * size, and emits frames through the supplied lora_frame_cb_t so the
 * same dedup / feed / JSON pipeline carries them.
 *
 * This is the Phase 3 Commit 2 primitive: manual trigger (env-driven)
 * focus on a single channel/time from the ring. Commit 3 adds the
 * idle/decoding/hold-down lifecycle; Commit 4 attaches automatic
 * promotion from the scanner.
 */

#ifndef FOCUSED_H
#define FOCUSED_H

#include "iq_ring.h"
#include "lora.h"

#include <stdint.h>
#include <stddef.h>

typedef struct focused_worker focused_worker_t;

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

/* Start the worker thread. start_sample = absolute sample index from
 * which to begin DDC; if start_sample is older than the live range,
 * the worker silently advances to the oldest live sample. */
int  focused_worker_start(focused_worker_t *w, uint64_t start_sample);

/* Ask the worker to stop after it drains everything currently in the
 * ring. Blocks until the worker thread joins. */
void focused_worker_stop_and_join(focused_worker_t *w);

/* Stats, mostly for stderr at shutdown. */
uint64_t focused_worker_samples_consumed(const focused_worker_t *w);
uint64_t focused_worker_samples_to_decoder(const focused_worker_t *w);
uint64_t focused_worker_frames_delivered(const focused_worker_t *w);

#endif
