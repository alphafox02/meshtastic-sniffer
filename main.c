/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: wideband Meshtastic LoRa receiver.
 *
 * Captures a single wide IQ slice from one SDR, channelizes into every
 * configured Meshtastic preset/channel, runs a LoRa CSS demod per
 * channel, and -- with keys supplied -- AES-CTR decrypts and decodes
 * the inner protobuf payload (text, position, nodeinfo, telemetry,
 * routing, traceroute, neighborinfo, waypoint, admin, etc.) in
 * parallel.
 *
 */

#include "channelizer.h"
#include "announce.h"
#include "archive.h"
#include "c2_dealer.h"
#include "feed.h"
#include "geofence.h"
#include "gpsd.h"
#include "pcap_out.h"
#include "psk_dict.h"
#include "schema.h"
#include "fftw_lock.h"
#include "file_src.h"
#include "keyset.h"
#include "lora.h"
#include "mesh_packet.h"
#include "meshtastic.h"
#include "options.h"
#include "scanner.h"
#include "sdr.h"
#include "sigmf.h"
#include "simd_kernels.h"
#include "web.h"

#include <complex.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>

#ifdef HAVE_HACKRF
#include "hackrf.h"
#endif
#ifdef HAVE_BLADERF
#include "bladerf.h"
#endif
#ifdef HAVE_RTLSDR
#include "rtlsdr.h"
#endif
#ifdef HAVE_SOAPYSDR
#include "soapysdr.h"
#endif
#ifdef HAVE_SDRPLAY
#include "sdrplay.h"
#endif
#ifdef HAVE_AIRSPY
#include "airspy.h"
#endif
#ifdef HAVE_UHD
#include "usrp.h"
#endif
#include "vita49.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

pid_t self_pid;
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ---- Global pipeline state ---- */

channelizer_t *g_channelizer = NULL;
static keyset_t      *g_keys = NULL;
static lora_decoder_t *g_demods[CHANNELIZER_MAX_CHANNELS];
static scanner_t     *g_scanner = NULL;
static uint64_t       g_grid_freqs[CHANNELIZER_MAX_CHANNELS];
static int            g_grid_bws[CHANNELIZER_MAX_CHANNELS];
static int            g_grid_count = 0;

/* Accessors used by web.c for /api endpoints. */
keyset_t *app_get_keyset(void) { return g_keys; }
int app_grid_count(void)       { return g_grid_count; }
const uint64_t *app_grid_freqs(void) { return g_grid_freqs; }
const int      *app_grid_bws  (void) { return g_grid_bws;   }

/* Heartbeat counters bumped from the sample / decode paths. */
static uint64_t g_samples_total = 0;
static uint64_t g_frames_total  = 0;
static uint64_t g_decrypts_total = 0;
static uint64_t g_offgrid_total = 0;

/* Optional IQ record sink: tees raw bytes from push_samples() to disk
 * so a power user can replay later (with different keys, against a
 * tuned demod, etc.) via --file=PATH. */
static FILE *g_iq_record_fp = NULL;

/* Per-channel rolling stats for --stats-json. Bumped from on_lora_frame
 * by channel id, dumped every 5s to stats-json file (rotates in place). */
typedef struct {
    uint64_t frames;
    uint64_t decrypted;
    double   snr_db_sum;
    int      snr_db_count;
    uint64_t bytes;
    /* Radio-layer parameters of this slot, captured at channel_create time
     * so the stats-json line has self-describing preset/sf/cr/bw without
     * the consumer re-deriving from frequency. */
    int      sf;
    int      cr;
    int      bw_hz;
    char     preset_name[24];
} chan_stat_t;
static chan_stat_t g_chan_stats[CHANNELIZER_MAX_CHANNELS];

void push_samples(sample_buf_t *buf)
{
    if (!buf) return;
    __atomic_add_fetch(&g_samples_total, buf->num, __ATOMIC_RELAXED);
    /* Tee raw IQ to disk before processing -- if the channelizer or
     * demod misbehaves, the captured file is still usable for replay. */
    if (g_iq_record_fp) {
        size_t bytes = (buf->format == SAMPLE_FMT_FLOAT) ? buf->num * 8 : buf->num * 2;
        fwrite(buf->samples, 1, bytes, g_iq_record_fp);
    }
    if (g_channelizer) {
        if (buf->format == SAMPLE_FMT_INT8)
            channelizer_process_int8(g_channelizer, buf->samples, buf->num);
        else if (buf->format == SAMPLE_FMT_FLOAT)
            channelizer_process_float(g_channelizer,
                                      (const float complex *)buf->samples, buf->num);
    }
    if (g_scanner) {
        if (buf->format == SAMPLE_FMT_INT8)
            scanner_feed_int8(g_scanner, buf->samples, buf->num);
        else if (buf->format == SAMPLE_FMT_FLOAT)
            scanner_feed_float(g_scanner,
                               (const float complex *)buf->samples, buf->num);
    }
    free(buf);
}

static void on_off_grid_discovery(const scanner_discovery_t *disc, void *user)
{
    (void)user;
    __atomic_add_fetch(&g_offgrid_total, 1, __ATOMIC_RELAXED);
    /* Emit a JSON discovery line on the same feed channel as packets. */
    char line[256];
    int n = snprintf(line, sizeof(line),
        "{\"event\":\"OFF_GRID_LORA\",\"f_hz\":%llu,\"snr_db\":%.1f,\"bw_estimate_hz\":%.0f}\n",
        (unsigned long long)disc->f_hz, (double)disc->snr_db, (double)disc->bw_hz_estimate);
    if (n < 0) return;
    fwrite(line, 1, (size_t)n, stdout); fflush(stdout);
    fprintf(stderr, "[scanner] off-grid LoRa-shaped energy at %.3f MHz, SNR %.1f dB\n",
            disc->f_hz / 1e6, (double)disc->snr_db);
}

/* ---- Pipeline glue: channelizer -> lora demod -> mesh packet -> feed ---- */

static uint64_t monotonic_us(void); /* defined below near the dedup ring */

/* Replay-attack flagging.
 *
 * Mesh frames carry a (from, packet_id) tuple. The Meshtastic firmware
 * itself dedups identical (from, packet_id) within a short window so
 * relayed retransmits don't reach the application layer twice -- but
 * a sniffer sees every transmission including the relays. Duplicates
 * within ~10 seconds are normal mesh retransmits (multi-path through
 * relay nodes); duplicates much later are suspicious and worth a
 * REPLAY_SUSPECTED alert.
 *
 * One alert per (from, packet_id) per process -- the operator decides
 * whether to investigate. Single-writer (only on_mesh_event touches
 * the ring), so no mutex needed.
 */
#define REPLAY_RING_SIZE       2048
#define REPLAY_FRESH_WINDOW_S  10  /* duplicates inside this are normal mesh */

typedef struct {
    uint32_t from;
    uint32_t packet_id;
    uint64_t first_seen_us;
    bool     alerted;
    bool     in_use;
} replay_entry_t;

static replay_entry_t g_replay_ring[REPLAY_RING_SIZE];
static size_t g_replay_next_slot = 0;

static void replay_check(const mesh_event_t *ev)
{
    const uint32_t from = ev->header.from;
    const uint32_t pid  = ev->header.packet_id;
    const uint64_t now  = monotonic_us();
    /* Linear scan; ring is small, hot in cache, single-writer. */
    for (size_t i = 0; i < REPLAY_RING_SIZE; ++i) {
        replay_entry_t *e = &g_replay_ring[i];
        if (!e->in_use) continue;
        if (e->from != from || e->packet_id != pid) continue;
        uint64_t delta_us = now - e->first_seen_us;
        if (!e->alerted &&
            delta_us > (uint64_t)REPLAY_FRESH_WINDOW_S * 1000000ULL) {
            char line[256];
            int n = snprintf(line, sizeof(line),
                "{\"event\":\"REPLAY_SUSPECTED\",\"from\":\"!%08x\","
                "\"packet_id\":%u,\"delta_s\":%.1f}\n",
                from, pid, (double)delta_us / 1.0e6);
            if (n > 0) {
                fwrite(line, 1, (size_t)n, stdout); fflush(stdout);
                if (opt_web_port > 0) web_publish_line(line, (size_t)n);
            }
            e->alerted = true;
        }
        return;
    }
    /* No match -- record. Overwrite the oldest slot (FIFO LRU). */
    replay_entry_t *e = &g_replay_ring[g_replay_next_slot];
    g_replay_next_slot = (g_replay_next_slot + 1) % REPLAY_RING_SIZE;
    e->from = from;
    e->packet_id = pid;
    e->first_seen_us = now;
    e->alerted = false;
    e->in_use = true;
}

/* Per-emit context handed to mesh_packet_decode_with_radio so the
 * post-decode callback can stamp slot id + RF-quality telemetry the
 * decode function itself doesn't know about (PFB slot index, CRC
 * validity, CFO, capture timestamp + accuracy class). */
typedef struct {
    int      channel_id;
    bool     has_crc;
    bool     payload_crc_ok;
    float    cfo_hz;
    uint64_t station_t_ns;     /* first-replica realtime ns */
    uint32_t station_t_acc_ns; /* operator-self-reported clock-discipline class */
} frame_emit_ctx_t;

static void on_mesh_event(const mesh_event_t *ev, void *user) {
    const frame_emit_ctx_t *ctx = (const frame_emit_ctx_t *)user;
    int channel_id = ctx ? ctx->channel_id : -1;
    if (ev->decrypted) {
        __atomic_add_fetch(&g_decrypts_total, 1, __ATOMIC_RELAXED);
        if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
            __atomic_add_fetch(&g_chan_stats[channel_id].decrypted, 1, __ATOMIC_RELAXED);
    }
    /* Stamp slot id + RF-quality telemetry onto the event copy so
     * feed.c can surface them in JSON without touching the decoder. */
    mesh_event_t stamped = *ev;
    stamped.slot_id = (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
                      ? channel_id : -1;
    if (ctx) {
        stamped.has_crc          = ctx->has_crc;
        stamped.payload_crc_ok   = ctx->payload_crc_ok;
        stamped.cfo_hz           = ctx->cfo_hz;
        stamped.station_t_ns     = ctx->station_t_ns;
        stamped.station_t_acc_ns = ctx->station_t_acc_ns;
        /* CRC-failed frames have corrupt bytes by definition. AES-CTR is
         * a stream cipher with no integrity check, so the protobuf
         * parser can "succeed" on garbage and produce fictitious
         * decoded fields (e.g. POSITION_APP with bogus lat/lon, or
         * TEXT_MESSAGE_APP with half-corrupt text). Force decrypted=
         * false here so feed.c suppresses the decoded-port block and
         * the operator only sees fields earned by intact bytes. */
        if (stamped.has_crc && !stamped.payload_crc_ok) {
            stamped.decrypted = false;
        }
    }
    replay_check(&stamped);
    feed_publish_event(&stamped);
}

/* Delayed best-pick dedup of PFB bin-leakage copies.
 *
 * Each LoRa transmission produces ~30 leakage replicas across adjacent
 * PFB output bins. Per-replica bit errors are independent across bins;
 * the cleanest decode is whichever bin had the highest SNR. Picking
 * the FIRST replica that arrives (eager emit) is random; picking the
 * highest-SNR replica is deterministically the best-quality copy.
 *
 * Algorithm:
 *   1. New replica arrives -> compute payload fingerprint.
 *   2. Find an existing cluster within Hamming distance 14 (real
 *      transmissions have fingerprint distance ~32; bit-error replicas
 *      ~1-5).
 *   3. If found and this replica's SNR is higher: replace the cluster's
 *      stored best.
 *   4. If not found: open a new cluster with this replica as best,
 *      schedule emit at now + DEDUP_WINDOW_US.
 *   5. Drainer thread polls every few ms; when a cluster's emit time
 *      passes, hand its best-stored replica to mesh_packet_decode_with_radio
 *      (single attempt, gets the cleanest SNR copy = best decrypt odds).
 *
 * One JSON line per real transmission, regardless of PFB leakage count.
 * Density-safe: 100 simultaneous distinct transmissions create 100
 * distinct clusters (random fingerprints don't collide within 14
 * Hamming bits). 30 ms window swallows leakage cluster from a single
 * chirp without merging adjacent unrelated transmissions. */
#define DEDUP_RING_SIZE         512
#define DEDUP_WINDOW_US         30000   /* 30 ms is well past leakage spread */
#define DEDUP_FP_HAMMING_THRESH 14      /* clean replicas: ~5 bit-flip differences */
/* When the new replica's payload CRC is bad, byte-level corruption pushes
 * the XOR-fold fingerprint far away from the clean cluster's fingerprint.
 * Loosen the match threshold so 8-15 bit errors per replica still fold.
 * The probability of an unrelated frame pair landing within Hamming 22 of
 * each other on uniformly random 64-bit fingerprints is ~0.6%, well below
 * the false-merge cost (one bogus extra observation in a 30 ms cluster) of
 * the alternative (15 phantom replicas as separate clusters). */
#define DEDUP_FP_HAMMING_THRESH_CRCFAIL 22
#define DEDUP_MAX_PAYLOAD       256

/* 64-bit XOR-fold fingerprint of the payload bytes. Two near-identical
 * byte arrays produce near-identical fingerprints; a single bit error
 * flips a single bit in the fingerprint. */
static uint64_t payload_fingerprint(const uint8_t *p, size_t n)
{
    uint64_t h = 0;
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t w;
        memcpy(&w, p + i, sizeof(w));
        h ^= w;
        h = (h << 1) | (h >> 63);
    }
    uint64_t tail = 0;
    for (size_t i = (n & ~7ULL); i < n; ++i)
        tail |= (uint64_t)p[i] << ((i - (n & ~7ULL)) * 8);
    return h ^ tail;
}

typedef struct {
    bool                in_use;
    uint64_t            fp;
    int                 sf;
    int                 bw_hz;
    uint64_t            emit_at_us;     /* now_us + window when first opened */
    uint64_t            first_seen_t_ns;/* CLOCK_REALTIME ns at first-replica arrival */
    /* Highest-SNR replica seen so far for this cluster. */
    float               best_snr_db;
    size_t              best_payload_len;
    uint8_t             best_payload[DEDUP_MAX_PAYLOAD];
    lora_frame_meta_t   best_meta;
    intptr_t            best_user;
    int                 replica_count;  /* for telemetry / debug */
} dedup_entry_t;

static dedup_entry_t   g_dedup[DEDUP_RING_SIZE];
static pthread_mutex_t g_dedup_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* CLOCK_REALTIME nanoseconds since the Unix epoch -- the value the mlat
 * solver consumes as `station_t_ns`. Accuracy is whatever your host
 * clock is disciplined to (NTP / chrony+PPS / GPSDO); reported by the
 * sniffer via `station_t_acc_ns` so the solver can weight observations. */
static uint64_t realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Buffer the replica into its cluster (matched by fingerprint), keeping
 * the highest-SNR copy seen so far. Returns true if a new cluster was
 * opened (= caller can stop here; the drainer will emit). */
static void dedup_buffer(const uint8_t *payload, size_t payload_len,
                         const lora_frame_meta_t *meta, intptr_t user)
{
    if (!payload || payload_len < 14 || payload_len > DEDUP_MAX_PAYLOAD) return;
    int sf = meta ? meta->sf    : 0;
    int bw = meta ? meta->bw_hz : 0;
    float snr = meta ? meta->snr_db : 0.0f;
    bool crc_bad = meta && meta->has_crc && !meta->payload_crc_ok;
    uint64_t fp = payload_fingerprint(payload, payload_len);
    uint64_t now_us = monotonic_us();

    /* Pick the matching threshold up-front: clean replicas use the tight
     * 14-bit window; CRC-failed replicas use the looser 22-bit window so
     * heavy byte-level corruption still folds into the right cluster
     * instead of forking 15 phantom siblings. */
    const int thresh = crc_bad ? DEDUP_FP_HAMMING_THRESH_CRCFAIL
                               : DEDUP_FP_HAMMING_THRESH;

    pthread_mutex_lock(&g_dedup_mu);
    dedup_entry_t *match = NULL;
    int free_slot = -1;
    for (int i = 0; i < DEDUP_RING_SIZE; ++i) {
        dedup_entry_t *e = &g_dedup[i];
        if (!e->in_use) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (e->sf != sf || e->bw_hz != bw) continue;
        int hd = __builtin_popcountll(e->fp ^ fp);
        if (hd <= thresh) { match = e; break; }
    }
    if (match) {
        match->replica_count++;
        if (snr > match->best_snr_db) {
            match->best_snr_db      = snr;
            match->best_payload_len = payload_len;
            memcpy(match->best_payload, payload, payload_len);
            if (meta) match->best_meta = *meta;
            match->best_user        = user;
            match->fp               = fp;   /* update to cleaner fp */
        }
    } else if (free_slot >= 0) {
        dedup_entry_t *e = &g_dedup[free_slot];
        e->in_use           = true;
        e->fp               = fp;
        e->sf               = sf;
        e->bw_hz            = bw;
        e->emit_at_us       = now_us + DEDUP_WINDOW_US;
        /* Realtime snapshot of FIRST replica arrival -- the closest we
         * can come to the actual on-air RX moment, modulo demod latency.
         * Subsequent higher-SNR replicas of the same cluster don't
         * update this; mlat wants a stable per-frame timestamp. */
        e->first_seen_t_ns  = realtime_ns();
        e->best_snr_db      = snr;
        e->best_payload_len = payload_len;
        memcpy(e->best_payload, payload, payload_len);
        if (meta) e->best_meta = *meta;
        e->best_user        = user;
        e->replica_count    = 1;
    }
    /* else: ring full -- silently drop. With RING_SIZE=512 and 30 ms
     * window, this would require ~17000 distinct clusters/sec, far
     * above any realistic urban Meshtastic load. */
    pthread_mutex_unlock(&g_dedup_mu);
}

/* Drainer thread: every few ms, emit any cluster whose window has
 * expired by handing its best-SNR replica to mesh_packet_decode_with_radio.
 * The decode runs OUTSIDE the dedup mutex so the decrypt + publish
 * path doesn't serialize against incoming replicas. */
static volatile bool g_dedup_drainer_run = false;
static pthread_t     g_dedup_drainer_tid;

static void dedup_emit_locked(const dedup_entry_t *e)
{
    intptr_t channel_id = e->best_user;
    __atomic_add_fetch(&g_frames_total, 1, __ATOMIC_RELAXED);
    if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS) {
        __atomic_add_fetch(&g_chan_stats[channel_id].frames, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_chan_stats[channel_id].bytes,
                           e->best_payload_len, __ATOMIC_RELAXED);
        g_chan_stats[channel_id].snr_db_sum   += (double)e->best_meta.snr_db;
        g_chan_stats[channel_id].snr_db_count += 1;
    }
    /* PCAP output: write the wire-shape frame (16-byte radio header +
     * still-encrypted payload) before any decrypt attempt, with the
     * current wall-clock timestamp. After dedup so we get one frame
     * per real transmission, not one per bin-leakage replica. */
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        pcap_out_write_frame(e->best_payload, e->best_payload_len,
                             (uint32_t)ts.tv_sec, (uint32_t)(ts.tv_nsec / 1000));
    }
    frame_emit_ctx_t ctx = {
        .channel_id       = (int)channel_id,
        .has_crc          = e->best_meta.has_crc,
        .payload_crc_ok   = e->best_meta.payload_crc_ok,
        .cfo_hz           = e->best_meta.cfo_hz,
        .station_t_ns     = e->first_seen_t_ns,
        .station_t_acc_ns = (uint32_t)opt_station_t_acc_ns,
    };
    mesh_packet_decode_with_radio(e->best_payload, e->best_payload_len,
                                  e->best_meta.rssi_db, e->best_meta.snr_db,
                                  e->best_meta.sf, e->best_meta.cr,
                                  e->best_meta.bw_hz,
                                  g_keys, on_mesh_event, &ctx);
}

/* Per-tick batch capacity. ~30 ms window x ~few hundred frames/sec
 * upper bound = handful of expirations per 5 ms tick on a busy mesh. */
#define DEDUP_DRAIN_BATCH 64

/* Drainer liveness + late-emit telemetry. The drainer ticks every 5 ms;
 * if the wall-clock interval between successful emits stretches past
 * 2x the dedup window without the thread exiting, the stats heartbeat
 * surfaces it. Stragglers count emits where now > emit_at + 2x window
 * (a leakage replica that arrived after the cluster was already
 * supposed to flush -- diagnoses CPU saturation). */
static _Atomic uint64_t g_drainer_last_tick_us = 0;
static _Atomic uint64_t g_dedup_stragglers     = 0;

static void *dedup_drainer_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "dedup-drain");
#endif
    /* Per-tick: ONE lock, scan ring, copy out all ready entries, unlock,
     * emit. That keeps lock-hold time bounded and decoupled from the
     * decode/publish path which can block on mqtt/web/stdout. */
    dedup_entry_t batch[DEDUP_DRAIN_BATCH];
    while (g_dedup_drainer_run) {
        usleep(5000); /* 5 ms tick = ~6 ticks per window */
        uint64_t now_us = monotonic_us();
        atomic_store_explicit(&g_drainer_last_tick_us, now_us, memory_order_relaxed);
        int n = 0;
        pthread_mutex_lock(&g_dedup_mu);
        for (int i = 0; i < DEDUP_RING_SIZE && n < DEDUP_DRAIN_BATCH; ++i) {
            dedup_entry_t *e = &g_dedup[i];
            if (e->in_use && now_us >= e->emit_at_us) {
                if (now_us > e->emit_at_us + 2ULL * DEDUP_WINDOW_US) {
                    atomic_fetch_add_explicit(&g_dedup_stragglers, 1, memory_order_relaxed);
                }
                batch[n++] = *e;
                e->in_use = false;
            }
        }
        pthread_mutex_unlock(&g_dedup_mu);
        for (int i = 0; i < n; ++i) dedup_emit_locked(&batch[i]);
    }
    return NULL;
}

static void dedup_drainer_start(void)
{
    g_dedup_drainer_run = true;
    pthread_create(&g_dedup_drainer_tid, NULL, dedup_drainer_thread, NULL);
}

static void dedup_drainer_stop(void)
{
    g_dedup_drainer_run = false;
    pthread_join(g_dedup_drainer_tid, NULL);
    /* Single locked sweep, emit outside the lock. */
    dedup_entry_t batch[DEDUP_RING_SIZE];
    int n = 0;
    pthread_mutex_lock(&g_dedup_mu);
    for (int i = 0; i < DEDUP_RING_SIZE; ++i) {
        if (g_dedup[i].in_use) {
            batch[n++] = g_dedup[i];
            g_dedup[i].in_use = false;
        }
    }
    pthread_mutex_unlock(&g_dedup_mu);
    for (int i = 0; i < n; ++i) dedup_emit_locked(&batch[i]);
}

/* Hot-path callback fires on EVERY LoRa frame from EVERY PFB output bin.
 * Including the leakage replicas. Just buffer here and return; the
 * drainer picks the highest-SNR replica per cluster after the dedup
 * window expires and only THEN runs decrypt + publish. */
static void on_lora_frame(const uint8_t *payload, size_t payload_len,
                          const lora_frame_meta_t *meta, void *user)
{
    intptr_t channel_id = (intptr_t)user;
    dedup_buffer(payload, payload_len, meta, channel_id);
}

/* Forward decl for the web SSE publisher (we don't include web.h here
 * to avoid a circular dep when only main needs to push raw lines). */
extern void web_publish_line(const char *json, size_t len);
/* Forward decl for the ZMQ PUB publisher; lets STATS heartbeats reach
 * meshtastic-fusion as part of the regular event stream. */
extern void zmq_pub_publish(const char *json, size_t len);

/* Friendly watchdog: warn loudly if samples don't flow in 2s and if no
 * LoRa frames decode in 30s. Fires each warning at most once. */
static void *watchdog_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "watchdog");
#endif
    bool warned_no_samples = false, warned_no_frames = false;
    int  ticks = 0;
    while (running) {
        for (int i = 0; i < 10 && running; ++i) usleep(100000); /* 1s */
        if (!running) break;
        ++ticks;

        if (!warned_no_samples && ticks >= 2) {
            uint64_t s = __atomic_load_n(&g_samples_total, __ATOMIC_RELAXED);
            if (s == 0) {
                fprintf(stderr,
                  "WARNING: no samples received from the SDR after 2s.\n"
                  "  Check: cable seated, antenna present, gain non-zero, no other\n"
                  "  process holding the device, the right --rate / --center for the\n"
                  "  hardware. With --hackrf, try `hackrf_info` from another terminal.\n");
                warned_no_samples = true;
            }
        }
        if (!warned_no_frames && ticks >= 30) {
            uint64_t f = __atomic_load_n(&g_frames_total, __ATOMIC_RELAXED);
            uint64_t s = __atomic_load_n(&g_samples_total, __ATOMIC_RELAXED);
            if (f == 0 && s > 0) {
                fprintf(stderr,
                  "NOTE: samples are flowing but no LoRa frames decoded in 30s.\n"
                  "  This is normal if no Meshtastic node is in range, or if the\n"
                  "  configured --presets / --region don't match local traffic.\n"
                  "  Try: --presets=all to scan every preset; --region matches\n"
                  "  whatever is set on your nearby nodes; gain may be too low.\n");
                warned_no_frames = true;
            }
        }
    }
    return NULL;
}

/* Heartbeat thread: stderr stats + SSE STATS event every 5 s. */
static void *stats_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "stats");
#endif
    uint64_t prev_samples = 0;
    int      stats_counter = 0;
    while (running) {
        for (int i = 0; i < 10 && running; ++i) usleep(100000); /* 1s, interruptible */
        if (!running) break;

        /* 5s stderr stats + optional per-channel JSON. */
        if (++stats_counter >= 5) {
            stats_counter = 0;
            uint64_t s   = __atomic_load_n(&g_samples_total,  __ATOMIC_RELAXED);
            uint64_t f   = __atomic_load_n(&g_frames_total,   __ATOMIC_RELAXED);
            uint64_t d   = __atomic_load_n(&g_decrypts_total, __ATOMIC_RELAXED);
            uint64_t og  = __atomic_load_n(&g_offgrid_total,  __ATOMIC_RELAXED);
            double rate_msps = (double)(s - prev_samples) / 5.0e6;
            prev_samples = s;
            /* Drainer liveness: if the dedup tick hasn't moved in 5x its
             * window (150 ms), the thread has died or is wedged. Log
             * once per stats heartbeat so it surfaces but doesn't spam. */
            uint64_t now_us = monotonic_us();
            uint64_t last_tick = atomic_load_explicit(&g_drainer_last_tick_us,
                                                     memory_order_relaxed);
            if (last_tick && now_us - last_tick > 5ULL * DEDUP_WINDOW_US) {
                fprintf(stderr, "[stats] WARN dedup drainer silent for %.0f ms -- frames may be backing up\n",
                        (double)(now_us - last_tick) / 1000.0);
            }
            /* Off-grid count only meaningful when the scanner is wired up.
             * In plain --decode the number is permanently 0; suppress it
             * everywhere it's surfaced rather than print a misleading zero. */
            const int scanner_on = (g_scanner != NULL);
            if (scanner_on)
                fprintf(stderr, "[stats] %.2f Msps in, %llu LoRa frames, %llu decrypted, %llu off-grid hits\n",
                        rate_msps, (unsigned long long)f, (unsigned long long)d,
                        (unsigned long long)og);
            else
                fprintf(stderr, "[stats] %.2f Msps in, %llu LoRa frames, %llu decrypted\n",
                        rate_msps, (unsigned long long)f, (unsigned long long)d);

            /* STATS heartbeat fan-out: web SSE for the local dashboard,
             * ZMQ PUB so meshtastic-fusion can populate per-sensor
             * msps / decrypt% in its Sensors tab. The "station" field
             * tags the source sniffer when --station-id is set;
             * fusion's subscriber loop falls back to the registry name
             * if absent. */
            char sline[320];
            int sn;
            const char *sid = opt_station_id ? opt_station_id : "";
            if (scanner_on)
                sn = snprintf(sline, sizeof(sline),
                    "{\"event\":\"STATS\",\"station\":\"%s\","
                    "\"msps\":%.2f,\"frames\":%llu,"
                    "\"decrypted\":%llu,\"off_grid\":%llu}\n",
                    sid, rate_msps, (unsigned long long)f,
                    (unsigned long long)d, (unsigned long long)og);
            else
                sn = snprintf(sline, sizeof(sline),
                    "{\"event\":\"STATS\",\"station\":\"%s\","
                    "\"msps\":%.2f,\"frames\":%llu,"
                    "\"decrypted\":%llu}\n",
                    sid, rate_msps, (unsigned long long)f,
                    (unsigned long long)d);
            if (sn > 0) {
                if (opt_web_port > 0) web_publish_line(sline, (size_t)sn);
                zmq_pub_publish(sline, (size_t)sn);
            }

            if (opt_stats_json) {
                FILE *sf = fopen(opt_stats_json, "w");
                if (sf) {
                    fprintf(sf, "{\"ts\":%ld,\"msps\":%.3f,\"frames\":%llu,"
                                "\"decrypted\":%llu,\"off_grid\":%llu,\"channels\":[",
                            (long)time(NULL), rate_msps,
                            (unsigned long long)f, (unsigned long long)d,
                            (unsigned long long)og);
                    int n_ch = channelizer_num_channels(g_channelizer);
                    for (int i = 0; i < n_ch && i < CHANNELIZER_MAX_CHANNELS; ++i) {
                        chan_stat_t *cs = &g_chan_stats[i];
                        double avg_snr = cs->snr_db_count
                            ? cs->snr_db_sum / (double)cs->snr_db_count : 0.0;
                        fprintf(sf, "%s{\"id\":%d", i ? "," : "", i);
                        if (cs->preset_name[0])
                            fprintf(sf, ",\"preset\":\"%s\"", cs->preset_name);
                        if (cs->sf)
                            fprintf(sf, ",\"sf\":%d,\"cr\":%d,\"bw_hz\":%d",
                                    cs->sf, cs->cr, cs->bw_hz);
                        fprintf(sf, ",\"frames\":%llu,\"decrypted\":%llu,"
                                    "\"avg_snr_db\":%.2f,\"bytes\":%llu}",
                                (unsigned long long)cs->frames,
                                (unsigned long long)cs->decrypted, avg_snr,
                                (unsigned long long)cs->bytes);
                    }
                    fprintf(sf, "]}\n");
                    fclose(sf);
                }
            }
        }
    }
    return NULL;
}

static void on_channel_baseband(int channel_id,
                                const float complex *samples, size_t n,
                                void *user)
{
    (void)user;
    if (channel_id < 0 || channel_id >= CHANNELIZER_MAX_CHANNELS) return;
    if (g_demods[channel_id])
        lora_decoder_feed(g_demods[channel_id], samples, n);
}

static int instantiate_channel(uint64_t f_hz, int bw_hz, int sf, int cr);

/* Add an extra-freq slot at runtime (called by web /api/extra-freq).
 * Caveat: mutates channelizer + g_demods while the SDR thread feeds samples.
 * Allocate everything first, then atomically bump count. Race window is benign
 * (new channel may miss the very next ~32k samples but doesn't corrupt). */
int app_add_runtime_extra_freq(uint64_t f_hz, int bw_hz, int sf, int cr)
{
    if (!g_channelizer) return -1;
    int id = instantiate_channel(f_hz, bw_hz, sf, cr);
    if (id < 0) return -1;
    /* Refresh scanner exclusion grid. */
    if (g_scanner)
        scanner_set_known_grid(g_scanner, g_grid_freqs, g_grid_bws, g_grid_count);
    return id;
}

/* ---- Build the channel set for the configured (region, presets) pair ---- */

static int instantiate_channel(uint64_t f_hz, int bw_hz, int sf, int cr)
{
    /* Skip channels whose passband doesn't fit inside the capture.
     * half_band == 0 (samp_rate exactly equals bw) means only an
     * exactly-centered channel works; that's still a valid case. */
    double half_band = samp_rate / 2.0 - bw_hz / 2.0;
    if (half_band < 0) return -1;
    double off = fabs((double)((int64_t)f_hz - (int64_t)center_freq));
    if (off > half_band) {
        if (verbose) {
            fprintf(stderr, "  skip %.3f MHz: outside passband (offset %.2f MHz, half %.2f MHz)\n",
                    f_hz / 1e6, off / 1e6, half_band / 1e6);
        }
        return -1;
    }

    /* The polyphase channelizer always emits critically sampled (output
     * rate = bw_hz), so the LoRa demod runs at os_factor=1 regardless
     * of the SDR-to-BW ratio. The fractional-STO compensation that the
     * cascade DDC needed for real radio (os_factor>=2) is unnecessary
     * here -- the PFB's prototype filter delivers integer-sample
     * alignment by construction. */
    int os_factor = 1;
    channel_cfg_t cfg = {
        .f_hz        = f_hz,
        .bw_hz       = bw_hz,
        .sf          = sf,
        .cr          = cr,
        .os_factor   = os_factor,
        .on_baseband = on_channel_baseband,
        .user        = NULL,
    };
    int id = channelizer_add_channel(g_channelizer, &cfg);
    if (id < 0) return -1;

    g_demods[id] = lora_decoder_create_os(sf, cr, bw_hz, os_factor);
    if (!g_demods[id]) return -1;
    /* Stash channel id in user pointer so on_lora_frame can attribute stats. */
    lora_decoder_set_callback(g_demods[id], on_lora_frame, (void *)(intptr_t)id);

    /* Capture this slot's radio params + preset name into per-channel stats
     * so the stats-json line is self-describing. */
    if (id >= 0 && id < CHANNELIZER_MAX_CHANNELS) {
        g_chan_stats[id].sf    = sf;
        g_chan_stats[id].cr    = cr;
        g_chan_stats[id].bw_hz = bw_hz;
        g_chan_stats[id].preset_name[0] = 0;
        for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
            const mesh_preset_def_t *d = &MESH_PRESETS[p];
            if (d->spread_factor == sf && d->coding_rate == cr &&
                (d->bw_hz_narrow == bw_hz || d->bw_hz_wide == bw_hz)) {
                strncpy(g_chan_stats[id].preset_name, d->channel_name,
                        sizeof(g_chan_stats[id].preset_name) - 1);
                break;
            }
        }
    }

    /* Track in the known-grid list so the scanner excludes this freq. */
    if (g_grid_count < CHANNELIZER_MAX_CHANNELS) {
        g_grid_freqs[g_grid_count] = f_hz;
        g_grid_bws[g_grid_count]   = bw_hz;
        ++g_grid_count;
    }
    return id;
}

static int build_channel_set(void)
{
    const mesh_region_t *region = mesh_lookup_region(opt_region ? opt_region : "US");
    if (!region) {
        fprintf(stderr, "unknown region '%s'\n", opt_region ? opt_region : "(null)");
        return -1;
    }

    /* Parse --presets csv: tokens separated by ',' or 'all' for everything. */
    const char *presets_csv = opt_preset_csv ? opt_preset_csv : "LongFast";
    bool want_all = (strcasecmp(presets_csv, "all") == 0);

    int total_added = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        const mesh_preset_def_t *preset = &MESH_PRESETS[p];

        bool selected = want_all;
        if (!selected) {
            char *dup = strdup(presets_csv);
            char *save = NULL;
            for (char *tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
                while (*tok == ' ' || *tok == '\t') ++tok;
                const mesh_preset_def_t *match = mesh_lookup_preset(tok);
                if (match && strcmp(match->name, preset->name) == 0) {
                    selected = true; break;
                }
            }
            free(dup);
        }
        if (!selected) continue;

        int bw = region->wide_lora ? preset->bw_hz_wide : preset->bw_hz_narrow;
        int slot_count = mesh_channel_count(region, bw);
        if (slot_count <= 0) continue;

        int added_for_preset = 0;
        for (int slot = 0; slot < slot_count; ++slot) {
            uint64_t f = mesh_channel_freq_hz(region, bw, slot);
            if (!f) break;
            if (instantiate_channel(f, bw, preset->spread_factor, preset->coding_rate) >= 0) {
                ++added_for_preset;
                ++total_added;
            }
        }
        fprintf(stderr, "preset %-13s: %d/%d slots added (BW %d kHz, SF%d, CR4/%d)\n",
                preset->name, added_for_preset, slot_count,
                bw / 1000, preset->spread_factor, preset->coding_rate);
    }

    /* User-supplied off-grid extras. */
    for (int i = 0; i < opt_extra_freq_count; ++i) {
        const extra_freq_t *e = &opt_extra_freqs[i];
        if (instantiate_channel(e->freq_hz, e->bw_hz, e->sf, e->cr) >= 0) {
            ++total_added;
            fprintf(stderr, "extra-freq %.3f MHz BW %d kHz SF%d CR4/%d added\n",
                    e->freq_hz / 1e6, e->bw_hz / 1000, e->sf, e->cr);
        }
    }

    return total_added;
}

/* ---- Pick sane defaults for center_freq + samp_rate when user didn't set them ---- */

/* Per-backend max sane sample rate. Picked so a casual user typing
 * "--hackrf --keys=default" gets a workable wideband stare without
 * having to figure out what their SDR can do. */
static uint32_t backend_default_rate(sdr_backend_t b)
{
    switch (b) {
    case SDR_BACKEND_HACKRF:   return 20000000;   /* 20 Msps -- US-all-presets coverage */
    case SDR_BACKEND_BLADERF:  return 20000000;   /* AD9361 capable of more, this fits everything */
    case SDR_BACKEND_USRP:     return 20000000;
    case SDR_BACKEND_AIRSPY:   return 10000000;   /* Airspy R2 native */
    case SDR_BACKEND_SDRPLAY:  return 10000000;   /* RSP1A/RSPdx comfortable */
    case SDR_BACKEND_RTLSDR:   return  2000000;   /* R820T2: rock-solid 2.0 Msps, integer 8x 250 kHz preset BW */
    case SDR_BACKEND_SOAPYSDR: return  2000000;   /* assume RTL-class via Soapy; safe default for 250 kHz alignment */
    case SDR_BACKEND_VITA49:   return        0;   /* set from VRT context packets */
    case SDR_BACKEND_FILE:     return        0;   /* set from SigMF or user --rate */
    default:                   return 10000000;
    }
}

static void resolve_rf_defaults(void)
{
    /* User-specified rate wins; otherwise pick from the backend table. */
    if (opt_sample_rate) {
        samp_rate = (double)opt_sample_rate;
    } else {
        samp_rate = (double)backend_default_rate(opt_sdr_backend);
    }
    center_freq = (double)opt_center_freq_hz;
    if (center_freq != 0.0) return;

    /* Derive: place center at the midpoint of the (region, preset) coverage. */
    const mesh_region_t *r = mesh_lookup_region(opt_region ? opt_region : "US");
    const char *presets = opt_preset_csv ? opt_preset_csv : "LongFast";

    if (!r) {
        center_freq = 910000000.0;  /* US ISM midpoint as fallback */
        return;
    }

    /* For "all" presets just use the region midpoint. */
    if (strcasecmp(presets, "all") == 0) {
        center_freq = (r->f_lo_mhz + r->f_hi_mhz) * 0.5e6;
        return;
    }

    /* Single-preset: place center at the midpoint of the channel grid. */
    char *dup = strdup(presets);
    char *save = NULL;
    char *first = strtok_r(dup, ",", &save);
    const mesh_preset_def_t *preset = first ? mesh_lookup_preset(first) : NULL;
    free(dup);

    if (!preset) {
        center_freq = (r->f_lo_mhz + r->f_hi_mhz) * 0.5e6;
        return;
    }

    int bw = r->wide_lora ? preset->bw_hz_wide : preset->bw_hz_narrow;
    int slots = mesh_channel_count(r, bw);
    if (slots <= 0) {
        center_freq = (r->f_lo_mhz + r->f_hi_mhz) * 0.5e6;
        return;
    }

    /* Snap to the slot midpoint so all 'slots' channels are covered if BW allows. */
    uint64_t f0 = mesh_channel_freq_hz(r, bw, 0);
    uint64_t fN = mesh_channel_freq_hz(r, bw, slots - 1);
    center_freq = (double)(f0 + fN) * 0.5;
    /* If the span > samp_rate, fall back to f0+samp_rate/2. */
    double span = (double)(fN - f0);
    if (span > samp_rate) center_freq = (double)f0 + samp_rate * 0.5 - bw * 0.5;
}

/* ---- Spawn the input source thread ---- */

static int start_input(pthread_t *tid)
{
    void *arg = NULL;
    void *(*fn)(void *) = NULL;
    const char *name = "input";

    switch (opt_sdr_backend) {
    case SDR_BACKEND_FILE: {
        if (!opt_input_file) { fprintf(stderr, "--file requires PATH\n"); return -1; }
        arg = file_src_setup(opt_input_file);
        fn  = file_src_thread; name = "file";
        break;
    }
    case SDR_BACKEND_VITA49:
        fn = vita49_thread; name = "vita49";
        break;
#ifdef HAVE_HACKRF
    case SDR_BACKEND_HACKRF:
        arg = hackrf_backend_setup(opt_sdr_serial);
        fn  = hackrf_stream_thread; name = "hackrf";
        break;
#endif
#ifdef HAVE_BLADERF
    case SDR_BACKEND_BLADERF: {
        int idx = opt_sdr_serial ? atoi(opt_sdr_serial) : 0;
        arg = bladerf_backend_setup(idx);
        fn  = bladerf_stream_thread; name = "bladerf";
        break;
    }
#endif
#ifdef HAVE_RTLSDR
    case SDR_BACKEND_RTLSDR:
        arg = rtlsdr_backend_setup(rtl_dev_index);
        fn  = rtlsdr_stream_thread; name = "rtlsdr";
        break;
#endif
#ifdef HAVE_SOAPYSDR
    case SDR_BACKEND_SOAPYSDR:
        fn = soapy_stream_thread; name = "soapy";
        break;
#endif
#ifdef HAVE_SDRPLAY
    case SDR_BACKEND_SDRPLAY:
        arg = sdrplay_setup(opt_sdr_serial);
        fn  = sdrplay_stream_thread; name = "sdrplay";
        break;
#endif
#ifdef HAVE_AIRSPY
    case SDR_BACKEND_AIRSPY: {
        uint64_t s = opt_sdr_serial ? strtoull(opt_sdr_serial, NULL, 16) : 0;
        arg = airspy_backend_setup(s);
        fn  = airspy_stream_thread; name = "airspy";
        break;
    }
#endif
#ifdef HAVE_UHD
    case SDR_BACKEND_USRP:
        arg = usrp_backend_setup(opt_sdr_serial);
        fn  = usrp_stream_thread; name = "usrp";
        break;
#endif
    default:
        fprintf(stderr, "no SDR/file/VITA-49 selected. See --help.\n");
        return -1;
    }
    if (!fn) {
        fprintf(stderr, "selected backend not compiled in.\n");
        return -1;
    }

    if (pthread_create(tid, NULL, fn, arg) != 0) {
        fprintf(stderr, "pthread_create(%s) failed\n", name);
        return -1;
    }
#ifdef _GNU_SOURCE
    pthread_setname_np(*tid, name);
#endif
    return 0;
}

/* ---- Channelizer self-test (synthetic tone) ---- */

typedef struct { int id; size_t nsamples; double power_sum; } chan_stats_t;

static void selftest_cb(int channel_id, const float complex *iq, size_t n, void *user)
{
    chan_stats_t *stats = (chan_stats_t *)user + channel_id;
    stats->id = channel_id;
    stats->nsamples += n;
    for (size_t i = 0; i < n; ++i) {
        float r = crealf(iq[i]); float im = cimagf(iq[i]);
        stats->power_sum += (double)(r * r + im * im);
    }
}

static int run_selftest(void)
{
    const uint32_t fs       = 20000000;
    const uint64_t f_center = 910000000;
    const mesh_region_t *us = mesh_lookup_region("US");
    const mesh_preset_def_t *lf = mesh_lookup_preset("LongFast");
    if (!us || !lf) return 1;

    int target_ch = 2;
    uint64_t f_tone = mesh_channel_freq_hz(us, lf->bw_hz_narrow, target_ch);

    channelizer_t *c = channelizer_create(f_center, fs);
    if (!c) return 1;

    enum { N_CH = 4 };
    chan_stats_t stats[N_CH] = {0};
    for (int i = 0; i < N_CH; ++i) {
        channel_cfg_t cfg = {
            .f_hz = mesh_channel_freq_hz(us, lf->bw_hz_narrow, i),
            .bw_hz = lf->bw_hz_narrow, .sf = lf->spread_factor, .cr = lf->coding_rate,
            .on_baseband = selftest_cb, .user = stats,
        };
        channelizer_add_channel(c, &cfg);
    }

    double phase_inc = 2.0 * M_PI * (double)((int64_t)f_tone - (int64_t)f_center) / (double)fs;
    size_t total_samples = (size_t)fs / 10;
    size_t block = 65536;
    int8_t *buf = malloc(block * 2);
    double phase = 0.0;
    size_t fed = 0;
    while (fed < total_samples) {
        size_t n = total_samples - fed;
        if (n > block) n = block;
        for (size_t i = 0; i < n; ++i) {
            buf[2*i]     = (int8_t)(cos(phase) * 100.0);
            buf[2*i + 1] = (int8_t)(sin(phase) * 100.0);
            phase += phase_inc;
        }
        channelizer_process_int8(c, buf, n);
        fed += n;
    }
    free(buf);

    fprintf(stderr, "selftest: tone at %.3f MHz (US LongFast ch%d), 0.1 sec @ 20 Msps\n",
            f_tone / 1e6, target_ch);
    for (int i = 0; i < N_CH; ++i) {
        double avg = stats[i].nsamples ? stats[i].power_sum / (double)stats[i].nsamples : 0.0;
        double db  = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
        fprintf(stderr, "  ch%d: %zu samples, mean power %.4f (%.2f dB) %s\n",
                i, stats[i].nsamples, avg, db, i == target_ch ? "<-- target" : "");
    }
    channelizer_destroy(c);
    return 0;
}

/* ---- AES + multi-key + protobuf end-to-end self-test ---- */

typedef struct {
    bool got; uint32_t portnum; char text[64]; char channel[32];
} st_capture_t;

static void st_event(const mesh_event_t *ev, void *user)
{
    st_capture_t *cap = (st_capture_t *)user;
    cap->got = true; cap->portnum = ev->portnum;
    if (ev->payload && ev->payload_len < sizeof(cap->text)) {
        memcpy(cap->text, ev->payload, ev->payload_len);
        cap->text[ev->payload_len] = 0;
    }
    strncpy(cap->channel, ev->channel_name, sizeof(cap->channel) - 1);
    feed_publish_event(ev);
}

static int aes_encrypt_ctr_test(const uint8_t *key, const uint8_t *iv,
                                const uint8_t *in, size_t in_len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0, finlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, in, (int)in_len);
    EVP_EncryptFinal_ex(ctx, out + outlen, &finlen);
    EVP_CIPHER_CTX_free(ctx);
    return outlen + finlen;
}

static int run_aes_selftest(void)
{
    const char *text = "Hello";
    uint8_t inner[64];
    size_t  inner_len = 0;
    inner[inner_len++] = 0x08; inner[inner_len++] = 0x01;
    inner[inner_len++] = 0x12; inner[inner_len++] = (uint8_t)strlen(text);
    memcpy(inner + inner_len, text, strlen(text));
    inner_len += strlen(text);

    keyset_t *keys = keyset_create();
    keyset_parse_spec(keys, "default");
    const keyset_entry_t *e = keyset_get(keys, 0);
    fprintf(stderr, "selftest-aes: keyset has %d entries; first hash=0x%02x\n",
            keys->n_entries, e ? e->channel_hash : 0xff);

    uint32_t to = 0xFFFFFFFFu, from = 0xDEADBEEFu, pid = 0x12345678u;

    uint8_t header[16] = {0};
    for (int i = 0; i < 4; ++i) header[i]    = (uint8_t)(to   >> (i*8));
    for (int i = 0; i < 4; ++i) header[4+i]  = (uint8_t)(from >> (i*8));
    for (int i = 0; i < 4; ++i) header[8+i]  = (uint8_t)(pid  >> (i*8));
    header[12] = 0x07; header[13] = e->channel_hash;

    uint8_t iv[16] = {0};
    for (int i = 0; i < 4; ++i) iv[i]    = (uint8_t)(pid  >> (i*8));
    for (int i = 0; i < 4; ++i) iv[8+i]  = (uint8_t)(from >> (i*8));

    uint8_t cipher[64];
    int clen = aes_encrypt_ctr_test(e->psk, iv, inner, inner_len, cipher);

    uint8_t frame[256];
    memcpy(frame, header, 16); memcpy(frame + 16, cipher, (size_t)clen);

    st_capture_t cap = {0};
    int rc = mesh_packet_decode(frame, 16 + (size_t)clen, keys, st_event, &cap);

    int pass = (rc == 0 && cap.got && cap.portnum == MESH_PORT_TEXT_MESSAGE
                && strcmp(cap.text, text) == 0);
    fprintf(stderr,
            "selftest-aes: rc=%d got=%d portnum=%u text='%s' channel='%s'  %s\n",
            rc, cap.got, cap.portnum, cap.text, cap.channel, pass ? "PASS" : "FAIL");
    keyset_destroy(keys);
    return pass ? 0 : 1;
}

/* ---- Live run ---- */

static int run_live(void)
{
    /* If --file=PATH was given and a .sigmf-meta sibling exists, pull
     * sample_rate / center_freq / datatype from it. User CLI flags
     * override (we only fill in when the user didn't set the field). */
    if (opt_sdr_backend == SDR_BACKEND_FILE && opt_input_file) {
        sigmf_meta_t m;
        if (sigmf_load_for_path(opt_input_file, &m)) {
            if (m.have_sample_rate && opt_sample_rate == 0)
                opt_sample_rate = (uint32_t)m.sample_rate;
            if (m.have_frequency && opt_center_freq_hz == 0)
                opt_center_freq_hz = (uint64_t)m.frequency_hz;
            if (m.have_datatype && iq_format == FMT_CI8)
                iq_format = m.datatype;
            fprintf(stderr, "sigmf: loaded metadata for %s "
                            "(rate=%g freq=%g datatype=%d)\n",
                    opt_input_file, m.sample_rate, m.frequency_hz,
                    (int)m.datatype);
        }
    }

    /* VITA-49: spawn the listener early, give context packets up to
     * 5s to populate samp_rate / center_freq before we resolve defaults. */
    pthread_t vita_tid = 0;
    bool vita_started = false;
    if (opt_sdr_backend == SDR_BACKEND_VITA49) {
        if (pthread_create(&vita_tid, NULL, vita49_thread, NULL) == 0) {
            vita_started = true;
#ifdef _GNU_SOURCE
            pthread_setname_np(vita_tid, "vita49");
#endif
            fprintf(stderr, "vita49: waiting up to 5s for context packets...\n");
            for (int i = 0; i < 50 && running; ++i) {
                if (samp_rate > 0.0 && center_freq > 0.0) break;
                usleep(100000);
            }
            if (samp_rate == 0.0 || center_freq == 0.0)
                fprintf(stderr, "vita49: no usable context packets in 5s; will resolve defaults\n");
        }
    }

    resolve_rf_defaults();
    if (samp_rate == 0.0) {
        fprintf(stderr, "ERROR: sample rate not set and no default for backend. "
                        "Pass --rate=HZ explicitly.\n");
        return 1;
    }
    fprintf(stderr, "RF: center %.3f MHz, rate %.3f Msps%s\n",
            center_freq / 1e6, samp_rate / 1e6,
            (opt_sdr_backend == SDR_BACKEND_VITA49) ? " (from VITA-49 context)" : "");
    fprintf(stderr, "    coverage window: %.3f .. %.3f MHz\n",
            (center_freq - samp_rate * 0.5) / 1e6,
            (center_freq + samp_rate * 0.5) / 1e6);

    /* Sanity-check user-supplied --center against the configured region's
     * spectrum. Warn-only -- the user may legitimately be on an SDR with a
     * frequency offset, or pointing at an off-grid signal -- but loudly
     * enough that a typo (--center=950e6 for a US deployment) is obvious. */
    if (opt_center_freq_hz != 0 && opt_region) {
        const mesh_region_t *r = mesh_lookup_region(opt_region);
        if (r) {
            double lo_hz = r->f_lo_mhz * 1.0e6;
            double hi_hz = r->f_hi_mhz * 1.0e6;
            double win_lo = center_freq - samp_rate * 0.5;
            double win_hi = center_freq + samp_rate * 0.5;
            if (win_hi < lo_hz || win_lo > hi_hz) {
                fprintf(stderr,
                    "WARNING: --center %.3f MHz puts the coverage window\n"
                    "         (%.3f .. %.3f MHz) entirely outside region %s\n"
                    "         (%.0f .. %.0f MHz). Did you mean a different region?\n",
                    center_freq / 1e6, win_lo / 1e6, win_hi / 1e6,
                    r->name, r->f_lo_mhz, r->f_hi_mhz);
            }
        }
    }

    /* Keyset:
     *   - --keys=...       (CLI csv)
     *   - --keys-file=...  (file, one spec per line, # comments)
     *   - default file at $XDG_CONFIG_HOME/meshtastic-sniffer/keys
     *                  or ~/.config/meshtastic-sniffer/keys
     *   - --share-url=URL  (meshtastic.org/e/ link parsed via web's decoder)
     *   - MESHTASTIC_KEYS env (already merged in options_parse)
     */
    g_keys = keyset_create();
    if (opt_keys_csv) keyset_parse_csv(g_keys, opt_keys_csv);

    /* Resolve default keys file path. */
    char default_keys_path[512] = {0};
    if (!opt_keys_file) {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        const char *home = getenv("HOME");
        if (xdg && *xdg)
            snprintf(default_keys_path, sizeof(default_keys_path),
                     "%s/meshtastic-sniffer/keys", xdg);
        else if (home && *home)
            snprintf(default_keys_path, sizeof(default_keys_path),
                     "%s/.config/meshtastic-sniffer/keys", home);
        if (default_keys_path[0] && access(default_keys_path, R_OK) == 0)
            opt_keys_file = default_keys_path;
    }
    if (opt_keys_file) {
        FILE *kf = fopen(opt_keys_file, "r");
        if (kf) {
            char line[1024]; int loaded = 0;
            while (fgets(line, sizeof(line), kf)) {
                char *p = line; while (*p == ' ' || *p == '\t') ++p;
                if (*p == 0 || *p == '#' || *p == '\n' || *p == '\r') continue;
                /* trim trailing whitespace/newline */
                size_t l = strlen(p);
                while (l > 0 && (p[l-1] == '\n' || p[l-1] == '\r' || p[l-1] == ' '))
                    p[--l] = 0;
                if (keyset_parse_spec(g_keys, p) == 0) ++loaded;
            }
            fclose(kf);
            fprintf(stderr, "keys-file: %s -- loaded %d entries\n", opt_keys_file, loaded);
        } else if (opt_keys_file != default_keys_path) {
            fprintf(stderr, "keys-file: cannot open %s\n", opt_keys_file);
        }
    }

    /* Share URL via the web decoder (which already understands the protobuf form). */
    if (opt_share_url) {
        extern int web_decode_share_url(keyset_t *ks, const char *url);
        int added = web_decode_share_url(g_keys, opt_share_url);
        if (added < 0)
            fprintf(stderr, "share-url: could not parse %s\n", opt_share_url);
        else
            fprintf(stderr, "share-url: imported %d channel(s)\n", added);
    }

    if (verbose) keyset_print(g_keys);

    /* Channelizer + per-channel demods */
    g_channelizer = channelizer_create((uint64_t)center_freq, (uint32_t)samp_rate);
    if (!g_channelizer) { fprintf(stderr, "channelizer_create failed\n"); return 1; }

    int n = build_channel_set();
    if (opt_op_mode != OP_MODE_SCAN && n <= 0) {
        fprintf(stderr, "no channels configured (region=%s presets=%s); nothing to decode.\n",
                opt_region, opt_preset_csv);
        /* Common gotcha on RTL-class SDRs: --rate is not a multiple of any
         * preset's LoRa channel bandwidth (125 / 250 / 500 kHz), so the
         * polyphase channelizer rejects every preset slot. Surface a
         * concrete hint with the next two integer-aligned rates the user
         * could try, instead of leaving them to guess. */
        const uint32_t rate = (uint32_t)samp_rate;
        const uint32_t bws[] = { 125000U, 250000U, 500000U };
        int any_aligned = 0;
        for (size_t i = 0; i < sizeof(bws)/sizeof(bws[0]); ++i)
            if (rate % bws[i] == 0) { any_aligned = 1; break; }
        if (!any_aligned) {
            uint32_t down = (rate / 250000U) * 250000U;
            uint32_t up   = down + 250000U;
            fprintf(stderr,
                "  hint: --rate=%u is not a multiple of any preset's LoRa BW\n"
                "        (125 / 250 / 500 kHz). Try --rate=%u or --rate=%u\n"
                "        (or omit --rate to take the backend default).\n",
                rate, down, up);
        }
        return 1;
    }
    if (n > 0)
        fprintf(stderr, "configured %d channel(s) total.\n", n);

    /* Scanner instance for --scan, --scan-and-decode, or --alert-off-grid.
     * Energy-detector FFT that fires off-grid LoRa-shaped alerts. */
    if (opt_op_mode != OP_MODE_DECODE || opt_alert_off_grid) {
        g_scanner = scanner_create((uint64_t)center_freq, (uint32_t)samp_rate, 4096);
        if (g_scanner) {
            scanner_set_known_grid(g_scanner, g_grid_freqs, g_grid_bws, g_grid_count);
            scanner_set_callback(g_scanner, on_off_grid_discovery, NULL);
            fprintf(stderr, "scanner: enabled with off-grid alerts "
                            "(4096-bin FFT, excluding %d grid channels)\n",
                    g_grid_count);
        }
    }

    /* Open IQ-record sink if requested. */
    if (opt_iq_record) {
        g_iq_record_fp = fopen(opt_iq_record, "wb");
        if (!g_iq_record_fp)
            fprintf(stderr, "iq-record: cannot open %s for write\n", opt_iq_record);
        else
            fprintf(stderr, "iq-record: writing raw IQ to %s\n", opt_iq_record);
    }

    feed_init();
    if (opt_pcap_path) pcap_out_init(opt_pcap_path, false);
    else if (opt_pcap_fifo) pcap_out_init(opt_pcap_fifo, true);
    if (opt_archive_dir) archive_init(opt_archive_dir);
    if (opt_geofence_file) geofence_init(opt_geofence_file);
    if (opt_psk_wordlist) {
        if (psk_dict_init(opt_psk_wordlist))
            fprintf(stderr, "psk-dict: dictionary attack active "
                            "against undecrypted frames\n");
        else
            fprintf(stderr, "psk-dict: failed to start; check the wordlist file\n");
    }
    if (opt_gpsd_endpoint) {
        if (gpsd_init(opt_gpsd_endpoint))
            fprintf(stderr, "gpsd: tagging events with station_lat/_lon/_alt_m from %s\n",
                    opt_gpsd_endpoint);
        else
            fprintf(stderr, "gpsd: failed to start client thread; events won't be tagged\n");
    }
    if (opt_announce_to) {
        if (!announce_init(opt_announce_to))
            fprintf(stderr, "announce: failed to start (bad URL?); fusion will not auto-discover this sensor\n");
    }
    if (opt_c2_dealer) {
        if (!c2_dealer_init(opt_c2_dealer))
            fprintf(stderr, "c2-dealer: failed to start; HTTP /api/* still available\n");
    }
    if (opt_web_port > 0) {
        web_init(opt_web_port);
        /* Make this visible on stdout (not just stderr) so users
         * launching from a GUI / through `tee` etc. see it. */
        fprintf(stdout, "Open http://localhost:%d to see decoded packets, channel activity, edit keys.\n",
                opt_web_port);
        fflush(stdout);
    } else {
        fprintf(stderr,
          "(no dashboard. add --web=8888 for a Leaflet map + Activity + Config tabs.)\n");
    }

    /* 5s stats heartbeat thread + 2s/30s friendly watchdogs. */
    pthread_t stats_tid, wd_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);
    pthread_create(&wd_tid,    NULL, watchdog_thread, NULL);

    /* Dedup drainer: emits the highest-SNR copy of each PFB bin-leakage
     * cluster after a 30 ms window. One JSON line per real transmission. */
    dedup_drainer_start();

    /* Spawn input thread (or reuse VITA-49 listener already started above). */
    pthread_t input_tid = 0;
    if (vita_started) {
        input_tid = vita_tid;
    } else if (start_input(&input_tid) < 0) {
        feed_shutdown();
        return 1;
    }

    /* Wait. push_samples() (called from input thread) does the work.
     * Poll instead of pause() to avoid a race where the input thread
     * sets running=0 + delivers SIGINT before we can enter pause(). */
    while (running)
        usleep(100000);

    pthread_join(input_tid, NULL);
    pthread_join(stats_tid, NULL);
    pthread_join(wd_tid, NULL);

    /* Stop the dedup drainer last; it flushes any pending clusters
     * before returning so the JSON stream gets the tail. */
    dedup_drainer_stop();

    /* Cleanup */
    if (g_iq_record_fp) { fclose(g_iq_record_fp); g_iq_record_fp = NULL; }
    web_shutdown();
    feed_shutdown();
    gpsd_shutdown();
    announce_shutdown();
    c2_dealer_shutdown();
    pcap_out_shutdown();
    psk_dict_shutdown();
    archive_shutdown();
    geofence_shutdown();
    for (int i = 0; i < CHANNELIZER_MAX_CHANNELS; ++i) {
        if (g_demods[i]) { lora_decoder_destroy(g_demods[i]); g_demods[i] = NULL; }
    }
    channelizer_destroy(g_channelizer); g_channelizer = NULL;
    if (g_scanner) { scanner_destroy(g_scanner); g_scanner = NULL; }
    keyset_destroy(g_keys);             g_keys = NULL;
    return 0;
}

/* ---- Entry point ---- */

int main(int argc, char **argv)
{
    self_pid = getpid();

    int rc = options_parse(argc, argv);
    if (rc == 1) return 0;        /* --help */
    if (rc >= 2 && rc != 100) return rc;

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    simd_init(opt_force_simd_generic);

    if (rc == 100) {              /* --selftest */
        feed_init();
        int a = run_selftest();
        int b = run_aes_selftest();
        feed_shutdown();
        return a | b;
    }

    fprintf(stderr,
            "meshtastic-sniffer (build " __DATE__ " " __TIME__ ")\n"
            "  %d regions, %d presets compiled in.\n",
            MESH_REGION_COUNT, (int)MESH_PRESET_COUNT);

    if (opt_print_schema) {
        schema_print();
        return 0;
    }

    if (opt_zmq_curve_keygen) {
#ifdef HAVE_ZMQ
        extern int zmq_curve_keypair(char *z85_public_key, char *z85_secret_key);
        char pub[41] = {0}, sec[41] = {0};
        if (zmq_curve_keypair(pub, sec) != 0) {
            fprintf(stderr, "zmq-curve-keygen: zmq_curve_keypair failed\n");
            return 1;
        }
        FILE *fs = fopen(opt_zmq_curve_keygen, "w");
        if (!fs) { perror(opt_zmq_curve_keygen); return 1; }
        fprintf(fs, "%s\n", sec); fclose(fs);
        char pubpath[1024];
        snprintf(pubpath, sizeof(pubpath), "%s.pub", opt_zmq_curve_keygen);
        FILE *fp = fopen(pubpath, "w");
        if (!fp) { perror(pubpath); return 1; }
        fprintf(fp, "%s\n", pub); fclose(fp);
        fprintf(stderr, "wrote secret to %s and public to %s\n",
                opt_zmq_curve_keygen, pubpath);
        fprintf(stderr, "fusion side: register this sensor with curve_pub=\"%s\"\n", pub);
        return 0;
#else
        fprintf(stderr, "zmq-curve-keygen: built without libzmq\n");
        return 1;
#endif
    }

    if (opt_list_devices) {
        fprintf(stdout, "Available SDR devices:\n");
#ifdef HAVE_HACKRF
        fprintf(stdout, "[hackrf]\n");  hackrf_backend_list();
#endif
#ifdef HAVE_BLADERF
        fprintf(stdout, "[bladerf]\n"); bladerf_backend_list();
#endif
#ifdef HAVE_RTLSDR
        fprintf(stdout, "[rtlsdr]\n");  rtlsdr_backend_list();
#endif
#ifdef HAVE_SOAPYSDR
        fprintf(stdout, "[soapy]\n");   soapy_list();
#endif
#ifdef HAVE_SDRPLAY
        fprintf(stdout, "[sdrplay]\n"); sdrplay_list();
#endif
#ifdef HAVE_AIRSPY
        fprintf(stdout, "[airspy]\n");  airspy_backend_list();
#endif
#ifdef HAVE_UHD
        fprintf(stdout, "[usrp]\n");    usrp_backend_list();
#endif
        return 0;
    }

    /* No backend selected and not --selftest -> nothing to do. */
    if (opt_sdr_backend == SDR_BACKEND_NONE) {
        fprintf(stderr, "no input source. use --hackrf, --rtlsdr, --file, etc., "
                        "or --selftest. See --help.\n");
        return 0;
    }

    return run_live();
}
