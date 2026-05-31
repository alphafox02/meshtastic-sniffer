/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Per-event raw-IQ snapshot store. On a qualifying wideband preamble
 * lock, captures a bounded window (default 50 ms pre / 100 ms post)
 * from the iq_ring and writes it to disk as a .cs8 / .cf32 file plus
 * a self-contained .json sidecar so the downstream fusion correlator
 * can ingest each snapshot without consulting the producing station.
 *
 * Decoder pipeline isolation:
 *   - producer (preamble-lock callback) takes the queue mutex,
 *     copies a tiny record, releases, returns. Never blocks on disk.
 *   - on queue full it drops the snapshot and bumps a counter; the
 *     decoder samples are never the thing that gets dropped.
 *   - a single dedicated writer thread owns ring extraction, file
 *     I/O, atomic temp-file + rename, and retention pruning.
 */

#ifndef IQ_SNAPSHOT_H
#define IQ_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>

typedef struct iq_ring iq_ring_t;

typedef struct iq_snapshot_cfg {
    /* Output directory; snapshots land in <dir>/YYYYMMDD/ (date-sharded
     * so retention can prune cheaply by day folder). Required. */
    const char *dir;
    /* Window around the preamble lock. Total = pre + post. */
    int         window_pre_ms;
    int         window_post_ms;
    /* Retention caps. Whichever fires first triggers a prune cycle. */
    long long   disk_cap_mb;
    long long   age_cap_seconds;
    /* SNR floor: locks below this are silently dropped, not queued. */
    double      min_snr_db;
    /* Provided by main.c at init. */
    iq_ring_t  *ring;
    double      sample_rate;
    const char *station_id;        /* may be NULL; sidecar still written */
    uint32_t    station_t_acc_ns;  /* self-reported clock-discipline class */
    int         queue_capacity;    /* records; default 64 if 0 */
} iq_snapshot_cfg_t;

int  iq_snapshot_init(const iq_snapshot_cfg_t *cfg);
void iq_snapshot_shutdown(void);
int  iq_snapshot_enabled(void);   /* 1 if init succeeded and not shut down */

/* Producer-side event record. preset_name is copied into an internal
 * buffer so the caller does not have to keep the pointer alive. */
typedef struct {
    uint64_t lock_sample_idx;
    uint64_t lock_t_ns;            /* CLOCK_REALTIME ns at lock */
    double   snr_db_at_lock;
    int      sf;
    int      cr;
    int      bw_hz;
    uint64_t freq_hz;
    char     preset_name[24];
} iq_snapshot_event_t;

/* Enqueue. Drops (silently, with a counter bump) if the queue is full
 * or the lock SNR is below cfg.min_snr_db. Safe to call from any
 * thread including the preamble-lock callback. */
void iq_snapshot_enqueue(const iq_snapshot_event_t *ev);

typedef struct {
    uint64_t kept;                 /* snapshots successfully written */
    uint64_t pruned;               /* files removed by the janitor */
    uint64_t dropped_queue_full;   /* producer-side drops */
    uint64_t dropped_below_snr;    /* producer-side drops (SNR gate) */
    uint64_t wait_timeout;         /* writer gave up waiting for ring */
    uint64_t missed_ring_window;   /* pre-window aged out before extract */
    uint64_t enqueued_total;       /* every call to iq_snapshot_enqueue */
} iq_snapshot_counters_t;

void iq_snapshot_get_counters(iq_snapshot_counters_t *out);

#endif
