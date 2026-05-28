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
#include "dedup.h"
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
#include <errno.h>
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
/* CRC tallies. Only frames with an explicit CRC on the wire (has_crc=true)
 * contribute; implicit-header frames are excluded from both buckets, so
 * g_crc_pass_total + g_crc_fail_total <= g_frames_total. */
static uint64_t g_crc_pass_total = 0;
static uint64_t g_crc_fail_total = 0;
static uint64_t g_offgrid_total = 0;

/* Optional IQ record sink: tees raw bytes from push_samples() to disk
 * so a power user can replay later (with different keys, against a
 * tuned demod, etc.) via --file=PATH.
 *
 * g_iq_record_target_cs8: derived from the output filename extension
 * (.cs8 -> 1, .cf32 -> 0). When SDR native is float but target is cs8
 * we quantize on the fly so the file is actually readable as cs8 on
 * replay. The pre-fix bug was: SoapySDR/USRP gave us float samples,
 * we wrote raw float bytes into a .cs8-extension file, then a later
 * --file --iq-format=cs8 replay read float bytes as int8 pairs and
 * got garbage that decoded as collapsed-SNR noise. */
static FILE   *g_iq_record_fp = NULL;
static int     g_iq_record_target_cs8 = 0;
static uint64_t g_iq_record_clip = 0;     /* count of samples >= 1.0 in magnitude */
static double  g_iq_record_peak_mag2 = 0; /* max |sample|^2 observed */

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
    uint64_t freq_hz;
    char     preset_name[24];
} chan_stat_t;
static chan_stat_t g_chan_stats[CHANNELIZER_MAX_CHANNELS];

/* ---- Sample pump: decouple SDR recv from DSP -------------------------
 *
 * SDR backends call push_samples() from their receive callback/thread. For
 * high-rate USRP capture, doing channelizer work inline means UHD cannot
 * return to uhd_rx_streamer_recv() quickly enough and the device FIFO can
 * overrun. The pump makes push_samples() enqueue and return; one processing
 * thread owns the original channelizer/scanner path.
 */
/* Base default: enough buffering for normal backends without hiding sustained
 * DSP backpressure behind a large queue. High-rate USRP capture needs more
 * burst cushion because UHD's recv thread must return quickly to keep the
 * device FIFO from overrunning while DSP rides the steady-state limit.
 * Override either default via MESHTASTIC_SAMPLE_QUEUE=N. */
#define SAMPLE_QUEUE_DEFAULT_CAP 64
#define SAMPLE_QUEUE_USRP_HIGH_RATE_CAP 256
#define SAMPLE_QUEUE_USRP_HIGH_RATE_HZ 20000000.0

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
    pthread_cond_t  drained;
    sample_buf_t  **ring;
    size_t          cap;
    size_t          head, tail, size;
    int             active;      /* processor currently owns one buffer */
    int             started;
    int             closing;
    pthread_t       tid;
    _Atomic uint64_t submitted;
    _Atomic uint64_t processed;
    _Atomic uint64_t queue_waits;
} sample_pump_t;

static sample_pump_t g_sample_pump = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
    .not_empty = PTHREAD_COND_INITIALIZER,
    .not_full = PTHREAD_COND_INITIALIZER,
    .drained = PTHREAD_COND_INITIALIZER,
};

static int sample_pump_stats_enabled(void)
{
    const char *e = getenv("MESHTASTIC_PFB_STATS");
    return e && *e && *e != '0';
}

static void process_sample_buf(sample_buf_t *buf)
{
    if (!buf) return;
    __atomic_add_fetch(&g_samples_total, buf->num, __ATOMIC_RELAXED);
    /* Tee raw IQ to disk before processing -- if the channelizer or
     * demod misbehaves, the captured file is still usable for replay.
     * For target=cs8 when SDR native is float, quantize on the fly so
     * the file is replay-compatible with --iq-format=cs8. Also track
     * peak magnitude and clip count so the user can see when the input
     * is near full-scale (clip count > 0 means quantization is losing
     * dynamic range and the SDR gain should come down). */
    if (g_iq_record_fp) {
        if (buf->format == SAMPLE_FMT_FLOAT && g_iq_record_target_cs8) {
            const float *flt = (const float *)buf->samples;
            int8_t *tmp = malloc(buf->num * 2);
            if (tmp) {
                for (size_t i = 0; i < buf->num; ++i) {
                    float ii = flt[2*i + 0];
                    float qq = flt[2*i + 1];
                    double mag2 = (double)ii * ii + (double)qq * qq;
                    if (mag2 > g_iq_record_peak_mag2) g_iq_record_peak_mag2 = mag2;
                    if (mag2 >= 1.0) g_iq_record_clip++;
                    /* +/-127.5 -> +/-127 after rounding. Clip to int8 range. */
                    int iq_i = (int)lrintf(ii * 127.0f);
                    int iq_q = (int)lrintf(qq * 127.0f);
                    if (iq_i >  127) iq_i =  127; else if (iq_i < -128) iq_i = -128;
                    if (iq_q >  127) iq_q =  127; else if (iq_q < -128) iq_q = -128;
                    tmp[2*i + 0] = (int8_t)iq_i;
                    tmp[2*i + 1] = (int8_t)iq_q;
                }
                fwrite(tmp, 1, buf->num * 2, g_iq_record_fp);
                free(tmp);
            }
        } else {
            size_t bytes = (buf->format == SAMPLE_FMT_FLOAT) ? buf->num * 8 : buf->num * 2;
            fwrite(buf->samples, 1, bytes, g_iq_record_fp);
        }
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

static void *sample_pump_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "sample-pump");
#endif
    for (;;) {
        pthread_mutex_lock(&g_sample_pump.mu);
        while (g_sample_pump.size == 0 && !g_sample_pump.closing)
            pthread_cond_wait(&g_sample_pump.not_empty, &g_sample_pump.mu);
        if (g_sample_pump.size == 0 && g_sample_pump.closing) {
            pthread_mutex_unlock(&g_sample_pump.mu);
            break;
        }
        sample_buf_t *buf = g_sample_pump.ring[g_sample_pump.head];
        g_sample_pump.head = (g_sample_pump.head + 1) % g_sample_pump.cap;
        g_sample_pump.size--;
        g_sample_pump.active = 1;
        pthread_cond_signal(&g_sample_pump.not_full);
        pthread_mutex_unlock(&g_sample_pump.mu);

        process_sample_buf(buf);
        atomic_fetch_add(&g_sample_pump.processed, 1);

        pthread_mutex_lock(&g_sample_pump.mu);
        g_sample_pump.active = 0;
        if (g_sample_pump.size == 0)
            pthread_cond_broadcast(&g_sample_pump.drained);
        pthread_mutex_unlock(&g_sample_pump.mu);
    }
    return NULL;
}

static int sample_queue_default_cap(void)
{
    if (opt_sdr_backend == SDR_BACKEND_USRP &&
        samp_rate >= SAMPLE_QUEUE_USRP_HIGH_RATE_HZ)
        return SAMPLE_QUEUE_USRP_HIGH_RATE_CAP;
    return SAMPLE_QUEUE_DEFAULT_CAP;
}

static int sample_pipeline_start(void)
{
    int cap = sample_queue_default_cap();
    const char *env = getenv("MESHTASTIC_SAMPLE_QUEUE");
    if (env && *env) {
        int v = atoi(env);
        if (v >= 1 && v <= 4096) cap = v;
    }
    pthread_mutex_lock(&g_sample_pump.mu);
    if (g_sample_pump.started) {
        pthread_mutex_unlock(&g_sample_pump.mu);
        return 0;
    }
    g_sample_pump.ring = calloc((size_t)cap, sizeof(*g_sample_pump.ring));
    if (!g_sample_pump.ring) {
        pthread_mutex_unlock(&g_sample_pump.mu);
        return -1;
    }
    g_sample_pump.cap = (size_t)cap;
    g_sample_pump.head = g_sample_pump.tail = g_sample_pump.size = 0;
    g_sample_pump.active = 0;
    g_sample_pump.closing = 0;
    atomic_store(&g_sample_pump.submitted, 0);
    atomic_store(&g_sample_pump.processed, 0);
    atomic_store(&g_sample_pump.queue_waits, 0);
    if (pthread_create(&g_sample_pump.tid, NULL, sample_pump_thread, NULL) != 0) {
        free(g_sample_pump.ring);
        g_sample_pump.ring = NULL;
        g_sample_pump.cap = 0;
        pthread_mutex_unlock(&g_sample_pump.mu);
        return -1;
    }
    g_sample_pump.started = 1;
    pthread_mutex_unlock(&g_sample_pump.mu);
    fprintf(stderr, "sample-pump: queue capacity %d buffers\n", cap);
    return 0;
}

void sample_pipeline_drain(void)
{
    pthread_mutex_lock(&g_sample_pump.mu);
    while (g_sample_pump.started &&
           (g_sample_pump.size > 0 || g_sample_pump.active))
        pthread_cond_wait(&g_sample_pump.drained, &g_sample_pump.mu);
    pthread_mutex_unlock(&g_sample_pump.mu);
}

static void sample_pipeline_stop(void)
{
    pthread_mutex_lock(&g_sample_pump.mu);
    if (!g_sample_pump.started) {
        pthread_mutex_unlock(&g_sample_pump.mu);
        return;
    }
    g_sample_pump.closing = 1;
    pthread_cond_broadcast(&g_sample_pump.not_empty);
    pthread_cond_broadcast(&g_sample_pump.not_full);
    pthread_mutex_unlock(&g_sample_pump.mu);

    pthread_join(g_sample_pump.tid, NULL);

    if (sample_pump_stats_enabled()) {
        fprintf(stderr, "sample-pump: submitted=%llu processed=%llu queue_waits=%llu\n",
                (unsigned long long)atomic_load(&g_sample_pump.submitted),
                (unsigned long long)atomic_load(&g_sample_pump.processed),
                (unsigned long long)atomic_load(&g_sample_pump.queue_waits));
    }

    pthread_mutex_lock(&g_sample_pump.mu);
    free(g_sample_pump.ring);
    g_sample_pump.ring = NULL;
    g_sample_pump.cap = 0;
    g_sample_pump.head = g_sample_pump.tail = g_sample_pump.size = 0;
    g_sample_pump.active = 0;
    g_sample_pump.started = 0;
    g_sample_pump.closing = 0;
    pthread_mutex_unlock(&g_sample_pump.mu);
}

void push_samples(sample_buf_t *buf)
{
    if (!buf) return;
    pthread_mutex_lock(&g_sample_pump.mu);
    if (!g_sample_pump.started || g_sample_pump.closing) {
        pthread_mutex_unlock(&g_sample_pump.mu);
        process_sample_buf(buf);
        return;
    }
    while (g_sample_pump.size == g_sample_pump.cap && !g_sample_pump.closing) {
        atomic_fetch_add(&g_sample_pump.queue_waits, 1);
        pthread_cond_wait(&g_sample_pump.not_full, &g_sample_pump.mu);
    }
    if (g_sample_pump.closing) {
        pthread_mutex_unlock(&g_sample_pump.mu);
        free(buf);
        return;
    }
    g_sample_pump.ring[g_sample_pump.tail] = buf;
    g_sample_pump.tail = (g_sample_pump.tail + 1) % g_sample_pump.cap;
    g_sample_pump.size++;
    atomic_fetch_add(&g_sample_pump.submitted, 1);
    pthread_cond_signal(&g_sample_pump.not_empty);
    pthread_mutex_unlock(&g_sample_pump.mu);
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

/* monotonic_us / realtime_ns / payload_fingerprint / dedup_entry_t / dedup_buffer
 * live in dedup.c (see dedup.h). */

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
    const uint64_t now  = dedup_monotonic_us();
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
    /* Stamp slot id + RF-quality telemetry onto the event copy so
     * feed.c can surface them in JSON without touching the decoder. */
    mesh_event_t stamped = *ev;
    stamped.slot_id = (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
                      ? channel_id : -1;
    if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
        stamped.freq_hz = g_chan_stats[channel_id].freq_hz;
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
    /* Count after the CRC-fail override so the stats counter agrees
     * with what the JSON output reports. A channel-hash-matched but
     * payload-CRC-failed frame isn't a successful decrypt -- AES-CTR
     * ran but produced garbage -- and surfacing it as "decrypted" in
     * stats but "decrypted:false" in JSON had operators wondering why
     * the numbers disagreed. */
    if (stamped.decrypted) {
        __atomic_add_fetch(&g_decrypts_total, 1, __ATOMIC_RELAXED);
        if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
            __atomic_add_fetch(&g_chan_stats[channel_id].decrypted, 1, __ATOMIC_RELAXED);
    }
    replay_check(&stamped);
    feed_publish_event(&stamped);
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
    if (e->best_meta.has_crc) {
        if (e->best_meta.payload_crc_ok)
            __atomic_add_fetch(&g_crc_pass_total, 1, __ATOMIC_RELAXED);
        else
            __atomic_add_fetch(&g_crc_fail_total, 1, __ATOMIC_RELAXED);
    }
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
        uint64_t now_us = dedup_monotonic_us();
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
            uint64_t cp  = __atomic_load_n(&g_crc_pass_total, __ATOMIC_RELAXED);
            uint64_t cf  = __atomic_load_n(&g_crc_fail_total, __ATOMIC_RELAXED);
            uint64_t ct  = cp + cf;
            /* No-CRC frames (implicit-header style) aren't counted toward the
             * pass/fail rate because there's no CRC field on the wire to check.
             * Surface their count alongside total so the f/ct gap is explained
             * instead of looking like silent failures. */
            uint64_t nc  = (f >= ct) ? (f - ct) : 0;
            char crc_buf[80];
            if (ct > 0)
                snprintf(crc_buf, sizeof(crc_buf), "CRC %.1f%% (%llu/%llu, %llu no-CRC)",
                         100.0 * (double)cp / (double)ct,
                         (unsigned long long)cp, (unsigned long long)ct,
                         (unsigned long long)nc);
            else
                snprintf(crc_buf, sizeof(crc_buf), "CRC -- (0/0, %llu no-CRC)",
                         (unsigned long long)nc);
            double rate_msps = (double)(s - prev_samples) / 5.0e6;
            prev_samples = s;
            /* Drainer liveness: if the dedup tick hasn't moved in 5x its
             * window (150 ms), the thread has died or is wedged. Log
             * once per stats heartbeat so it surfaces but doesn't spam. */
            uint64_t now_us = dedup_monotonic_us();
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
                fprintf(stderr, "[stats] %.2f Msps in, %llu LoRa frames, %s, %llu decrypted, %llu off-grid hits\n",
                        rate_msps, (unsigned long long)f, crc_buf,
                        (unsigned long long)d, (unsigned long long)og);
            else
                fprintf(stderr, "[stats] %.2f Msps in, %llu LoRa frames, %s, %llu decrypted\n",
                        rate_msps, (unsigned long long)f, crc_buf,
                        (unsigned long long)d);

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
    /* Per-slot RF carrier enables the SFO drift compensation path; without
     * it the decoder's gr-lora_sdr-style SFO logic stays inert. */
    lora_decoder_set_center_freq(g_demods[id], (double)f_hz);
    /* Stash channel id in user pointer so on_lora_frame can attribute stats. */
    lora_decoder_set_callback(g_demods[id], on_lora_frame, (void *)(intptr_t)id);

    /* Capture this slot's radio params + preset name into per-channel stats
     * so the stats-json line is self-describing. */
    if (id >= 0 && id < CHANNELIZER_MAX_CHANNELS) {
        g_chan_stats[id].sf      = sf;
        g_chan_stats[id].cr      = cr;
        g_chan_stats[id].bw_hz   = bw_hz;
        g_chan_stats[id].freq_hz = f_hz;
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

/* ---- Channelizer adjacent-channel-rejection sweep ----------------------
 *
 * For each unique LoRa bandwidth in the configured region, sweep a CW
 * tone across every channel grid slot that fits inside the SDR window,
 * register a sink on every slot, and accumulate per-sink mean power.
 * Reports each (source, leak) pair's absolute power + relative rejection
 * to a CSV under /tmp and an aggregate worst/median/best summary to
 * stderr. This is the bench-side answer to "how much does an in-band
 * emitter leak into adjacent grid channels," replacing the window-
 * function handwave that used to be in ARCHITECTURE.md.
 *
 * Float-IQ noise floor would be cleaner but the existing selftest path
 * uses int8 + scale-100 CW because that exercises the same cs8 ingest
 * we use on HackRF/B205 captures; staying consistent keeps the apples
 * apples and surfaces any cs8-specific quantization in the same number.
 */

typedef struct { double acr; int bw; int src; int leak; } acr_record_t;

static int acr_record_cmp(const void *a, const void *b)
{
    double da = ((const acr_record_t *)a)->acr;
    double db = ((const acr_record_t *)b)->acr;
    return (da < db) ? -1 : (da > db) ? 1 : 0;
}

int run_selftest_rejection(void)
{
    const char *region_name = opt_region ? opt_region : "US";
    const mesh_region_t *r = mesh_lookup_region(region_name);
    if (!r) {
        fprintf(stderr, "selftest-rejection: unknown region '%s'\n", region_name);
        return 1;
    }
    /* Default 20 Msps if --rate wasn't given; default center to region mid. */
    uint32_t fs = samp_rate > 0.0 ? (uint32_t)samp_rate : 20000000u;
    uint64_t f_center = center_freq > 0.0
        ? (uint64_t)center_freq
        : (uint64_t)((r->f_lo_mhz + r->f_hi_mhz) * 0.5 * 1e6);

    /* Collect the unique bandwidths used by this region. */
    int bw_set[8] = {0}; int n_bw = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        int bw = r->wide_lora ? MESH_PRESETS[p].bw_hz_wide
                              : MESH_PRESETS[p].bw_hz_narrow;
        int seen = 0;
        for (int i = 0; i < n_bw; ++i) if (bw_set[i] == bw) { seen = 1; break; }
        if (!seen && n_bw < (int)(sizeof(bw_set)/sizeof(bw_set[0])))
            bw_set[n_bw++] = bw;
    }
    /* Sort smallest-to-largest just for readable output. */
    for (int i = 0; i < n_bw; ++i)
        for (int j = i + 1; j < n_bw; ++j)
            if (bw_set[j] < bw_set[i]) { int t = bw_set[i]; bw_set[i] = bw_set[j]; bw_set[j] = t; }

    /* Open output CSV under /tmp -- never under tests/results/, to keep the
     * repo working tree clean across runs. */
    char ts[32], csvpath[256];
    time_t now = time(NULL); struct tm tmv; gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
    snprintf(csvpath, sizeof(csvpath),
             "/tmp/meshtastic-pfb-rejection-%s.csv", ts);
    FILE *csv = fopen(csvpath, "w");
    if (!csv) {
        fprintf(stderr, "selftest-rejection: cannot open %s: %s\n",
                csvpath, strerror(errno));
        return 1;
    }
    fprintf(csv,
            "rate_hz,bw_hz,source_ch,leak_ch,target_dbfs,leak_dbfs,acr_db,n_samples\n");

    fprintf(stderr,
            "selftest-rejection: region=%s center=%.3f MHz rate=%u sps\n"
            "selftest-rejection: writing %s\n",
            r->name, f_center / 1e6, fs, csvpath);

    int total_records = 0, records_cap = 0;
    acr_record_t *records = NULL;

    double rf_lo = (double)f_center - 0.5 * (double)fs;
    double rf_hi = (double)f_center + 0.5 * (double)fs;

    for (int g = 0; g < n_bw; ++g) {
        int bw_hz = bw_set[g];
        if (fs % (uint32_t)bw_hz != 0) {
            fprintf(stderr, "selftest-rejection:  BW=%d kHz skipped (rate %u not a multiple)\n",
                    bw_hz / 1000, fs);
            continue;
        }
        /* Which grid slots fit inside the SDR window? */
        int n_slots = mesh_channel_count(r, bw_hz);
        int *fit = malloc(sizeof(int) * (size_t)(n_slots > 0 ? n_slots : 1));
        if (!fit) { fclose(csv); free(records); return 1; }
        int n_fit = 0;
        for (int s = 0; s < n_slots; ++s) {
            double f = (double)mesh_channel_freq_hz(r, bw_hz, s);
            if (f >= rf_lo && f <= rf_hi) fit[n_fit++] = s;
        }
        if (n_fit < 2) {
            fprintf(stderr, "selftest-rejection:  BW=%d kHz has only %d slots in window; skipped\n",
                    bw_hz / 1000, n_fit);
            free(fit);
            continue;
        }
        int M = (int)(fs / (uint32_t)bw_hz);
        fprintf(stderr,
                "selftest-rejection:  BW=%d kHz  M=%d  %d slots in window\n",
                bw_hz / 1000, M, n_fit);

        /* For each source position: fresh channelizer, register every
         * in-window slot as a sink, inject CW at source, dump powers. */
        for (int src_idx = 0; src_idx < n_fit; ++src_idx) {
            int src_slot = fit[src_idx];
            uint64_t f_tone = mesh_channel_freq_hz(r, bw_hz, src_slot);
            channelizer_t *c = channelizer_create(f_center, fs);
            if (!c) { fprintf(stderr, "selftest-rejection: channelizer_create failed\n"); free(fit); fclose(csv); free(records); return 1; }

            chan_stats_t *stats = calloc((size_t)n_fit, sizeof(*stats));
            if (!stats) { channelizer_destroy(c); free(fit); fclose(csv); free(records); return 1; }

            for (int k = 0; k < n_fit; ++k) {
                channel_cfg_t cfg = {
                    .f_hz = mesh_channel_freq_hz(r, bw_hz, fit[k]),
                    .bw_hz = bw_hz, .sf = 7, .cr = 5,
                    .on_baseband = selftest_cb, .user = stats,
                };
                channelizer_add_channel(c, &cfg);
            }

            /* Synthesize 0.1 s of CW at the source slot's center frequency. */
            double phase_inc = 2.0 * M_PI
                * (double)((int64_t)f_tone - (int64_t)f_center) / (double)fs;
            size_t total_samples = fs / 10;
            const size_t block = 65536;
            int8_t *buf = malloc(block * 2);
            if (!buf) { channelizer_destroy(c); free(stats); free(fit); fclose(csv); free(records); return 1; }
            double phase = 0.0;
            const double amp = 100.0;       /* matches run_selftest()'s scale */
            for (size_t fed = 0; fed < total_samples; ) {
                size_t n = total_samples - fed;
                if (n > block) n = block;
                for (size_t i = 0; i < n; ++i) {
                    buf[2*i]     = (int8_t)(cos(phase) * amp);
                    buf[2*i + 1] = (int8_t)(sin(phase) * amp);
                    phase += phase_inc;
                }
                channelizer_process_int8(c, buf, n);
                fed += n;
            }
            free(buf);

            /* Read out per-sink mean power and write CSV rows. */
            double target_avg = stats[src_idx].nsamples
                ? stats[src_idx].power_sum / (double)stats[src_idx].nsamples
                : 0.0;
            double target_db = target_avg > 0.0 ? 10.0 * log10(target_avg) : -200.0;

            for (int k = 0; k < n_fit; ++k) {
                if (k == src_idx) continue;
                double leak_avg = stats[k].nsamples
                    ? stats[k].power_sum / (double)stats[k].nsamples
                    : 0.0;
                double leak_db = leak_avg > 0.0 ? 10.0 * log10(leak_avg) : -200.0;
                double acr = target_db - leak_db;
                fprintf(csv, "%u,%d,%d,%d,%.3f,%.3f,%.3f,%zu\n",
                        fs, bw_hz, src_slot, fit[k],
                        target_db, leak_db, acr, stats[k].nsamples);

                if (total_records >= records_cap) {
                    int new_cap = records_cap ? records_cap * 2 : 1024;
                    acr_record_t *nr = realloc(records, sizeof(*nr) * (size_t)new_cap);
                    if (!nr) { channelizer_destroy(c); free(stats); free(fit); fclose(csv); free(records); return 1; }
                    records = nr;
                    records_cap = new_cap;
                }
                records[total_records++] = (acr_record_t){
                    .acr = acr, .bw = bw_hz, .src = src_slot, .leak = fit[k] };
            }

            /* IMPORTANT: destroy channelizer FIRST -- pfb_flush() inside
             * waits for any worker that still holds a reference to stats
             * via the sink's user pointer. Freeing stats earlier would
             * be a use-after-free in the worker's last callback. */
            channelizer_destroy(c);
            free(stats);
        }
        free(fit);
    }
    fclose(csv);

    if (total_records == 0) {
        fprintf(stderr,
                "selftest-rejection: no measurements taken (window too narrow for the grid?)\n");
        free(records);
        return 1;
    }

    /* Sort ascending so records[0] is worst (smallest ACR). */
    qsort(records, (size_t)total_records, sizeof(*records), acr_record_cmp);
    acr_record_t worst = records[0];
    acr_record_t best  = records[total_records - 1];
    acr_record_t median = records[total_records / 2];
    double sum = 0.0;
    for (int i = 0; i < total_records; ++i) sum += records[i].acr;
    double mean = sum / (double)total_records;

    fprintf(stderr,
            "selftest-rejection: %d (source,leak) pairs measured\n"
            "  worst  ACR %.2f dB  BW=%d kHz  source=%d  leak=%d\n"
            "  median ACR %.2f dB  BW=%d kHz  source=%d  leak=%d\n"
            "  best   ACR %.2f dB  BW=%d kHz  source=%d  leak=%d\n"
            "  mean   ACR %.2f dB\n"
            "  CSV: %s\n",
            total_records,
            worst.acr,  worst.bw / 1000,  worst.src,  worst.leak,
            median.acr, median.bw / 1000, median.src, median.leak,
            best.acr,   best.bw / 1000,   best.src,   best.leak,
            mean, csvpath);

    /* CI gate: worst ACR must stay >= 40 dB. Intentionally loose; measured
     * is ~50 dB so 40 dB catches a real regression without firing on
     * normal measurement noise. */
    const double acr_floor_db = 40.0;
    int gate_failed = (worst.acr < acr_floor_db);
    fprintf(stderr, "selftest-rejection: regression gate (worst ACR >= %.0f dB): %s\n",
            acr_floor_db, gate_failed ? "FAIL" : "PASS");

    free(records);
    return gate_failed ? 1 : 0;
}

/* ---- Channelizer ACR vs source amplitude sweep ------------------------
 *
 * Same per-(BW, source) sweep as run_selftest_rejection, but each source
 * position is exercised at multiple input amplitudes. The FIR + FFT path
 * is linear by construction, so what this test actually surfaces is
 * where the cs8 ingest's quantization noise floor sits relative to the
 * source tone: at low amplitudes the leak bins are dominated by that
 * floor and ACR appears small; once the tone is well above the floor
 * the measured ACR converges on the channelizer's structural value
 * (matching run_selftest_rejection's full-amp result).
 *
 * Useful for documenting where the cs8 path's measurement floor lies,
 * not for proving "linearity" -- linearity is a property of the code,
 * already true.
 */

static int double_cmp(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da < db) ? -1 : (da > db) ? 1 : 0;
}

int run_selftest_rejection_amplitude(void)
{
    const char *region_name = opt_region ? opt_region : "US";
    const mesh_region_t *r = mesh_lookup_region(region_name);
    if (!r) {
        fprintf(stderr, "selftest-rejection-amp: unknown region '%s'\n", region_name);
        return 1;
    }
    uint32_t fs = samp_rate > 0.0 ? (uint32_t)samp_rate : 20000000u;
    uint64_t f_center = center_freq > 0.0
        ? (uint64_t)center_freq
        : (uint64_t)((r->f_lo_mhz + r->f_hi_mhz) * 0.5 * 1e6);

    /* Amplitude set chosen per the test plan; dBFS referenced to int8 peak ±127. */
    static const double amps_dbfs[] = { -40.0, -20.0, -10.0, -3.0, -0.1 };
    const int n_amps = (int)(sizeof(amps_dbfs) / sizeof(amps_dbfs[0]));

    int bw_set[8] = {0}; int n_bw = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        int bw = r->wide_lora ? MESH_PRESETS[p].bw_hz_wide
                              : MESH_PRESETS[p].bw_hz_narrow;
        int seen = 0;
        for (int i = 0; i < n_bw; ++i) if (bw_set[i] == bw) { seen = 1; break; }
        if (!seen && n_bw < (int)(sizeof(bw_set)/sizeof(bw_set[0])))
            bw_set[n_bw++] = bw;
    }
    for (int i = 0; i < n_bw; ++i)
        for (int j = i + 1; j < n_bw; ++j)
            if (bw_set[j] < bw_set[i]) { int t = bw_set[i]; bw_set[i] = bw_set[j]; bw_set[j] = t; }

    char ts[32], csvpath[256];
    time_t now = time(NULL); struct tm tmv; gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
    snprintf(csvpath, sizeof(csvpath),
             "/tmp/meshtastic-pfb-rejection-amplitude-%s.csv", ts);
    FILE *csv = fopen(csvpath, "w");
    if (!csv) {
        fprintf(stderr, "selftest-rejection-amp: cannot open %s: %s\n",
                csvpath, strerror(errno));
        return 1;
    }
    fprintf(csv,
            "rate_hz,bw_hz,source_ch,amplitude_dbfs,target_dbfs,"
            "median_other_dbfs,worst_other_dbfs,worst_relative_db\n");

    fprintf(stderr,
            "selftest-rejection-amp: region=%s center=%.3f MHz rate=%u sps\n"
            "selftest-rejection-amp: amplitudes (dBFS): ", r->name, f_center / 1e6, fs);
    for (int a = 0; a < n_amps; ++a) fprintf(stderr, "%+.1f%s", amps_dbfs[a], a + 1 < n_amps ? ", " : "");
    fprintf(stderr, "\nselftest-rejection-amp: writing %s\n", csvpath);

    /* Per-amplitude worst-relative tracker for the summary. */
    double *worst_rel_at_amp = calloc((size_t)n_amps, sizeof(double));
    for (int a = 0; a < n_amps; ++a) worst_rel_at_amp[a] = 1e9; /* init to "no measurement" */

    double rf_lo = (double)f_center - 0.5 * (double)fs;
    double rf_hi = (double)f_center + 0.5 * (double)fs;

    for (int g = 0; g < n_bw; ++g) {
        int bw_hz = bw_set[g];
        if (fs % (uint32_t)bw_hz != 0) continue;

        int n_slots = mesh_channel_count(r, bw_hz);
        int *fit = malloc(sizeof(int) * (size_t)(n_slots > 0 ? n_slots : 1));
        if (!fit) { fclose(csv); free(worst_rel_at_amp); return 1; }
        int n_fit = 0;
        for (int s = 0; s < n_slots; ++s) {
            double f = (double)mesh_channel_freq_hz(r, bw_hz, s);
            if (f >= rf_lo && f <= rf_hi) fit[n_fit++] = s;
        }
        if (n_fit < 2) { free(fit); continue; }
        int M = (int)(fs / (uint32_t)bw_hz);
        fprintf(stderr,
                "selftest-rejection-amp:  BW=%d kHz  M=%d  %d slots in window\n",
                bw_hz / 1000, M, n_fit);

        double *other_db = malloc(sizeof(double) * (size_t)n_fit);
        if (!other_db) { free(fit); fclose(csv); free(worst_rel_at_amp); return 1; }

        for (int a = 0; a < n_amps; ++a) {
            double amp_int = pow(10.0, amps_dbfs[a] / 20.0) * 127.0;

            for (int src_idx = 0; src_idx < n_fit; ++src_idx) {
                int src_slot = fit[src_idx];
                uint64_t f_tone = mesh_channel_freq_hz(r, bw_hz, src_slot);

                channelizer_t *c = channelizer_create(f_center, fs);
                if (!c) { free(other_db); free(fit); fclose(csv); free(worst_rel_at_amp); return 1; }

                chan_stats_t *stats = calloc((size_t)n_fit, sizeof(*stats));
                if (!stats) { channelizer_destroy(c); free(other_db); free(fit); fclose(csv); free(worst_rel_at_amp); return 1; }

                for (int k = 0; k < n_fit; ++k) {
                    channel_cfg_t cfg = {
                        .f_hz = mesh_channel_freq_hz(r, bw_hz, fit[k]),
                        .bw_hz = bw_hz, .sf = 7, .cr = 5,
                        .on_baseband = selftest_cb, .user = stats,
                    };
                    channelizer_add_channel(c, &cfg);
                }

                double phase_inc = 2.0 * M_PI
                    * (double)((int64_t)f_tone - (int64_t)f_center) / (double)fs;
                size_t total_samples = fs / 10;
                const size_t block = 65536;
                int8_t *buf = malloc(block * 2);
                if (!buf) { channelizer_destroy(c); free(stats); free(other_db); free(fit); fclose(csv); free(worst_rel_at_amp); return 1; }
                double phase = 0.0;
                for (size_t fed = 0; fed < total_samples; ) {
                    size_t n = total_samples - fed;
                    if (n > block) n = block;
                    for (size_t i = 0; i < n; ++i) {
                        double ci = cos(phase) * amp_int;
                        double si = sin(phase) * amp_int;
                        /* Clamp to int8 range (only relevant at -0.1 dBFS edge cases). */
                        if (ci >  127.0) ci =  127.0; else if (ci < -128.0) ci = -128.0;
                        if (si >  127.0) si =  127.0; else if (si < -128.0) si = -128.0;
                        buf[2*i]     = (int8_t)ci;
                        buf[2*i + 1] = (int8_t)si;
                        phase += phase_inc;
                    }
                    channelizer_process_int8(c, buf, n);
                    fed += n;
                }
                free(buf);

                double target_avg = stats[src_idx].nsamples
                    ? stats[src_idx].power_sum / (double)stats[src_idx].nsamples
                    : 0.0;
                double target_db = target_avg > 0.0 ? 10.0 * log10(target_avg) : -200.0;

                int n_other = 0;
                for (int k = 0; k < n_fit; ++k) {
                    if (k == src_idx) continue;
                    double avg = stats[k].nsamples
                        ? stats[k].power_sum / (double)stats[k].nsamples
                        : 0.0;
                    other_db[n_other++] = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
                }
                /* qsort ascending: median at middle, worst (largest leak) at end. */
                qsort(other_db, (size_t)n_other, sizeof(double), double_cmp);
                double median_other = other_db[n_other / 2];
                double worst_other  = other_db[n_other - 1];
                double worst_rel    = target_db - worst_other;

                fprintf(csv, "%u,%d,%d,%+.3f,%.3f,%.3f,%.3f,%.3f\n",
                        fs, bw_hz, src_slot, amps_dbfs[a],
                        target_db, median_other, worst_other, worst_rel);

                if (worst_rel < worst_rel_at_amp[a])
                    worst_rel_at_amp[a] = worst_rel;

                channelizer_destroy(c);
                free(stats);
            }
        }
        free(other_db);
        free(fit);
    }
    fclose(csv);

    fprintf(stderr, "selftest-rejection-amp: worst relative rejection by amplitude:\n");
    int valid = 0;
    double min_rel = 1e9, max_rel = -1e9;
    for (int a = 0; a < n_amps; ++a) {
        if (worst_rel_at_amp[a] >= 1e9) {
            fprintf(stderr, "  %+6.1f dBFS:  (no data)\n", amps_dbfs[a]);
            continue;
        }
        fprintf(stderr, "  %+6.1f dBFS: %7.2f dB\n", amps_dbfs[a], worst_rel_at_amp[a]);
        if (worst_rel_at_amp[a] < min_rel) min_rel = worst_rel_at_amp[a];
        if (worst_rel_at_amp[a] > max_rel) max_rel = worst_rel_at_amp[a];
        valid++;
    }
    if (valid >= 2) {
        double spread = max_rel - min_rel;
        int monotonic_rising = 1;
        for (int a = 1; a < n_amps; ++a) {
            if (worst_rel_at_amp[a] >= 1e9 || worst_rel_at_amp[a-1] >= 1e9) continue;
            if (worst_rel_at_amp[a] < worst_rel_at_amp[a-1] - 0.5) { monotonic_rising = 0; break; }
        }
        fprintf(stderr,
                "selftest-rejection-amp: spread of worst-case ACR across amplitudes = %.2f dB\n",
                spread);
        if (spread < 1.0)
            fprintf(stderr, "  shape: flat across the amplitude range\n");
        else if (monotonic_rising)
            fprintf(stderr,
                    "  shape: worst-case ACR rises monotonically with input amplitude --\n"
                    "         consistent with the cs8 ingest's quantization floor setting the\n"
                    "         measurement ceiling at low dBFS; the channelizer's structural\n"
                    "         rejection becomes visible once the tone clears the floor.\n");
        else
            fprintf(stderr,
                    "  shape: non-monotonic by %.2f dB across the range; inspect the CSV\n",
                    spread);
    }
    fprintf(stderr, "selftest-rejection-amp: CSV: %s\n", csvpath);

    free(worst_rel_at_amp);
    return 0;
}

/* ---- Two-tone adjacent-channel test --------------------------------
 *
 * Strong tone in channel A, weak tone in adjacent channel B, both fed
 * through the cs8 ingest. Measures B's recovered bin power with and
 * without A present. If the channelizer is linear (it is, by
 * construction) the two numbers match: A leaks into B at the
 * structural ACR floor, far below B's own power, so B's bin reading
 * is unchanged.
 *
 * If field operators see close-range desense and this test shows no
 * software desense, the conclusion the README already states is
 * confirmed: the desense is in the SDR front end, not our processing.
 */

static int run_one_tone_pair(uint64_t f_center, uint32_t fs, int bw_hz,
                             int n_fit, const int *fit,
                             int target_idx /* index into fit[] */,
                             uint64_t f_strong, double amp_strong,
                             uint64_t f_weak,   double amp_weak,
                             double *out_target_dbfs)
{
    channelizer_t *c = channelizer_create(f_center, fs);
    if (!c) return -1;
    chan_stats_t *stats = calloc((size_t)n_fit, sizeof(*stats));
    if (!stats) { channelizer_destroy(c); return -1; }
    for (int k = 0; k < n_fit; ++k) {
        channel_cfg_t cfg = {
            .f_hz = mesh_channel_freq_hz(mesh_lookup_region(opt_region ? opt_region : "US"),
                                          bw_hz, fit[k]),
            .bw_hz = bw_hz, .sf = 7, .cr = 5,
            .on_baseband = selftest_cb, .user = stats,
        };
        channelizer_add_channel(c, &cfg);
    }
    double phase_a = 0.0, phase_b = 0.0;
    double inc_a = 2.0 * M_PI * (double)((int64_t)f_strong - (int64_t)f_center) / (double)fs;
    double inc_b = 2.0 * M_PI * (double)((int64_t)f_weak   - (int64_t)f_center) / (double)fs;
    size_t total_samples = fs / 10;
    const size_t block = 65536;
    int8_t *buf = malloc(block * 2);
    if (!buf) { channelizer_destroy(c); free(stats); return -1; }
    for (size_t fed = 0; fed < total_samples; ) {
        size_t n = total_samples - fed; if (n > block) n = block;
        for (size_t i = 0; i < n; ++i) {
            double ci = cos(phase_a) * amp_strong + cos(phase_b) * amp_weak;
            double si = sin(phase_a) * amp_strong + sin(phase_b) * amp_weak;
            if (ci >  127.0) ci =  127.0; else if (ci < -128.0) ci = -128.0;
            if (si >  127.0) si =  127.0; else if (si < -128.0) si = -128.0;
            buf[2*i]     = (int8_t)ci;
            buf[2*i + 1] = (int8_t)si;
            phase_a += inc_a;
            phase_b += inc_b;
        }
        channelizer_process_int8(c, buf, n);
        fed += n;
    }
    free(buf);
    double avg = stats[target_idx].nsamples
        ? stats[target_idx].power_sum / (double)stats[target_idx].nsamples
        : 0.0;
    *out_target_dbfs = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
    channelizer_destroy(c);
    free(stats);
    return 0;
}

int run_selftest_rejection_twotone(void)
{
    const char *region_name = opt_region ? opt_region : "US";
    const mesh_region_t *r = mesh_lookup_region(region_name);
    if (!r) {
        fprintf(stderr, "selftest-rejection-twotone: unknown region '%s'\n", region_name);
        return 1;
    }
    uint32_t fs = samp_rate > 0.0 ? (uint32_t)samp_rate : 20000000u;
    uint64_t f_center = center_freq > 0.0
        ? (uint64_t)center_freq
        : (uint64_t)((r->f_lo_mhz + r->f_hi_mhz) * 0.5 * 1e6);

    int bw_set[8] = {0}; int n_bw = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        int bw = r->wide_lora ? MESH_PRESETS[p].bw_hz_wide
                              : MESH_PRESETS[p].bw_hz_narrow;
        int seen = 0;
        for (int i = 0; i < n_bw; ++i) if (bw_set[i] == bw) { seen = 1; break; }
        if (!seen && n_bw < (int)(sizeof(bw_set)/sizeof(bw_set[0])))
            bw_set[n_bw++] = bw;
    }
    for (int i = 0; i < n_bw; ++i)
        for (int j = i + 1; j < n_bw; ++j)
            if (bw_set[j] < bw_set[i]) { int t = bw_set[i]; bw_set[i] = bw_set[j]; bw_set[j] = t; }

    /* Strong-tone amplitudes to sweep (dBFS). Weak fixed at -20 dBFS so
     * it clears the cs8 quantization floor (~28 dB worst ACR at -20 dBFS
     * per the amplitude sweep) but stays well below the strong tone. */
    static const double strong_dbfs[] = { -20.0, -10.0, -3.0, -0.1 };
    const int n_strong = (int)(sizeof(strong_dbfs) / sizeof(strong_dbfs[0]));
    const double weak_dbfs = -20.0;
    const double weak_amp = pow(10.0, weak_dbfs / 20.0) * 127.0;

    char ts[32], csvpath[256];
    time_t now = time(NULL); struct tm tmv; gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
    snprintf(csvpath, sizeof(csvpath),
             "/tmp/meshtastic-pfb-rejection-twotone-%s.csv", ts);
    FILE *csv = fopen(csvpath, "w");
    if (!csv) {
        fprintf(stderr, "selftest-rejection-twotone: cannot open %s: %s\n",
                csvpath, strerror(errno));
        return 1;
    }
    fprintf(csv,
            "rate_hz,bw_hz,strong_ch,strong_dbfs,weak_ch,weak_dbfs,"
            "weak_power_alone_dbfs,weak_power_with_strong_dbfs,desense_db\n");
    fprintf(stderr,
            "selftest-rejection-twotone: region=%s center=%.3f MHz rate=%u sps\n"
            "selftest-rejection-twotone: writing %s\n",
            r->name, f_center / 1e6, fs, csvpath);

    double rf_lo = (double)f_center - 0.5 * (double)fs;
    double rf_hi = (double)f_center + 0.5 * (double)fs;
    double max_abs_desense = 0.0;

    for (int g = 0; g < n_bw; ++g) {
        int bw_hz = bw_set[g];
        if (fs % (uint32_t)bw_hz != 0) continue;
        int n_slots = mesh_channel_count(r, bw_hz);
        int *fit = malloc(sizeof(int) * (size_t)(n_slots > 0 ? n_slots : 1));
        if (!fit) { fclose(csv); return 1; }
        int n_fit = 0;
        for (int s = 0; s < n_slots; ++s) {
            double f = (double)mesh_channel_freq_hz(r, bw_hz, s);
            if (f >= rf_lo && f <= rf_hi) fit[n_fit++] = s;
        }
        if (n_fit < 2) { free(fit); continue; }

        /* Strong = middle of window, weak = strong+1. */
        int strong_idx = n_fit / 2;
        int weak_idx   = strong_idx + 1;
        if (weak_idx >= n_fit) weak_idx = strong_idx - 1;
        int strong_slot = fit[strong_idx];
        int weak_slot   = fit[weak_idx];
        uint64_t f_strong = mesh_channel_freq_hz(r, bw_hz, strong_slot);
        uint64_t f_weak   = mesh_channel_freq_hz(r, bw_hz, weak_slot);

        fprintf(stderr,
                "selftest-rejection-twotone:  BW=%d kHz strong=slot%d weak=slot%d\n",
                bw_hz / 1000, strong_slot, weak_slot);

        for (int a = 0; a < n_strong; ++a) {
            double amp_strong = pow(10.0, strong_dbfs[a] / 20.0) * 127.0;

            /* Baseline: weak tone only. */
            double weak_alone_dbfs = -200.0;
            if (run_one_tone_pair(f_center, fs, bw_hz, n_fit, fit, weak_idx,
                                   f_strong, 0.0, f_weak, weak_amp,
                                   &weak_alone_dbfs) < 0) {
                fclose(csv); free(fit); return 1;
            }
            /* With strong tone present. */
            double weak_with_strong_dbfs = -200.0;
            if (run_one_tone_pair(f_center, fs, bw_hz, n_fit, fit, weak_idx,
                                   f_strong, amp_strong, f_weak, weak_amp,
                                   &weak_with_strong_dbfs) < 0) {
                fclose(csv); free(fit); return 1;
            }
            double desense = weak_with_strong_dbfs - weak_alone_dbfs;
            fprintf(csv, "%u,%d,%d,%+.3f,%d,%+.3f,%.3f,%.3f,%+.3f\n",
                    fs, bw_hz, strong_slot, strong_dbfs[a],
                    weak_slot, weak_dbfs,
                    weak_alone_dbfs, weak_with_strong_dbfs, desense);
            if (fabs(desense) > max_abs_desense) max_abs_desense = fabs(desense);
            fprintf(stderr,
                    "  strong=%+5.1f dBFS:  weak alone %.2f dB,  weak+strong %.2f dB,  desense %+5.2f dB\n",
                    strong_dbfs[a], weak_alone_dbfs, weak_with_strong_dbfs, desense);
        }
        free(fit);
    }
    fclose(csv);

    fprintf(stderr,
            "selftest-rejection-twotone: max |desense| = %.2f dB\n"
            "  shape: %s\n"
            "  CSV: %s\n",
            max_abs_desense,
            max_abs_desense < 1.0
                ? "no software desense observed; field desense (if any) is SDR front-end side"
                : "non-zero software desense; inspect CSV",
            csvpath);
    return 0;
}

/* ---- Off-bin tone leakage -----------------------------------------
 *
 * Real-world emitters drift off the integer-bin grid (crystal tolerance,
 * temperature, doppler). For each bandwidth group, inject a tone at
 * (source_ch_center + delta*bw) for delta in {0, 1/8, 1/4, 3/8, 1/2}
 * and record how the energy spreads across nearby output bins.
 *
 * Informs the off-grid scanner's bandwidth-estimator thresholds:
 * a tone at exactly half a bin off-center splits its energy between
 * two grid bins, so an off-grid emitter never sits cleanly in one
 * channel even if the scanner placed a sink at the right BW.
 */

int run_selftest_rejection_offbin(void)
{
    const char *region_name = opt_region ? opt_region : "US";
    const mesh_region_t *r = mesh_lookup_region(region_name);
    if (!r) {
        fprintf(stderr, "selftest-rejection-offbin: unknown region '%s'\n", region_name);
        return 1;
    }
    uint32_t fs = samp_rate > 0.0 ? (uint32_t)samp_rate : 20000000u;
    uint64_t f_center = center_freq > 0.0
        ? (uint64_t)center_freq
        : (uint64_t)((r->f_lo_mhz + r->f_hi_mhz) * 0.5 * 1e6);

    int bw_set[8] = {0}; int n_bw = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        int bw = r->wide_lora ? MESH_PRESETS[p].bw_hz_wide
                              : MESH_PRESETS[p].bw_hz_narrow;
        int seen = 0;
        for (int i = 0; i < n_bw; ++i) if (bw_set[i] == bw) { seen = 1; break; }
        if (!seen && n_bw < (int)(sizeof(bw_set)/sizeof(bw_set[0])))
            bw_set[n_bw++] = bw;
    }
    for (int i = 0; i < n_bw; ++i)
        for (int j = i + 1; j < n_bw; ++j)
            if (bw_set[j] < bw_set[i]) { int t = bw_set[i]; bw_set[i] = bw_set[j]; bw_set[j] = t; }

    static const double offset_frac[] = { 0.0, 0.125, 0.25, 0.375, 0.5 };
    const int n_off = (int)(sizeof(offset_frac) / sizeof(offset_frac[0]));

    char ts[32], csvpath[256];
    time_t now = time(NULL); struct tm tmv; gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
    snprintf(csvpath, sizeof(csvpath),
             "/tmp/meshtastic-pfb-rejection-offbin-%s.csv", ts);
    FILE *csv = fopen(csvpath, "w");
    if (!csv) {
        fprintf(stderr, "selftest-rejection-offbin: cannot open %s: %s\n",
                csvpath, strerror(errno));
        return 1;
    }
    fprintf(csv,
            "rate_hz,bw_hz,source_ch,source_offset_bw_fraction,leak_ch_offset,power_dbfs,relative_db\n");
    fprintf(stderr,
            "selftest-rejection-offbin: region=%s center=%.3f MHz rate=%u sps\n"
            "selftest-rejection-offbin: writing %s\n",
            r->name, f_center / 1e6, fs, csvpath);

    /* Show a small leak-offset window around the source. */
    const int leak_window = 2; /* -2..+2 */

    double rf_lo = (double)f_center - 0.5 * (double)fs;
    double rf_hi = (double)f_center + 0.5 * (double)fs;

    for (int g = 0; g < n_bw; ++g) {
        int bw_hz = bw_set[g];
        if (fs % (uint32_t)bw_hz != 0) continue;
        int n_slots = mesh_channel_count(r, bw_hz);
        int *fit = malloc(sizeof(int) * (size_t)(n_slots > 0 ? n_slots : 1));
        if (!fit) { fclose(csv); return 1; }
        int n_fit = 0;
        for (int s = 0; s < n_slots; ++s) {
            double f = (double)mesh_channel_freq_hz(r, bw_hz, s);
            if (f >= rf_lo && f <= rf_hi) fit[n_fit++] = s;
        }
        if (n_fit < 1 + 2 * leak_window) { free(fit); continue; }

        int src_idx  = n_fit / 2;
        int src_slot = fit[src_idx];

        fprintf(stderr,
                "selftest-rejection-offbin:  BW=%d kHz source=slot%d\n",
                bw_hz / 1000, src_slot);

        for (int o = 0; o < n_off; ++o) {
            double f_tone = (double)mesh_channel_freq_hz(r, bw_hz, src_slot)
                          + offset_frac[o] * (double)bw_hz;

            channelizer_t *c = channelizer_create(f_center, fs);
            if (!c) { free(fit); fclose(csv); return 1; }
            chan_stats_t *stats = calloc((size_t)n_fit, sizeof(*stats));
            if (!stats) { channelizer_destroy(c); free(fit); fclose(csv); return 1; }
            for (int k = 0; k < n_fit; ++k) {
                channel_cfg_t cfg = {
                    .f_hz = mesh_channel_freq_hz(r, bw_hz, fit[k]),
                    .bw_hz = bw_hz, .sf = 7, .cr = 5,
                    .on_baseband = selftest_cb, .user = stats,
                };
                channelizer_add_channel(c, &cfg);
            }
            double phase = 0.0;
            double phase_inc = 2.0 * M_PI * (f_tone - (double)f_center) / (double)fs;
            const double amp = pow(10.0, -3.0 / 20.0) * 127.0;  /* -3 dBFS */
            size_t total_samples = fs / 10;
            const size_t block = 65536;
            int8_t *buf = malloc(block * 2);
            if (!buf) { channelizer_destroy(c); free(stats); free(fit); fclose(csv); return 1; }
            for (size_t fed = 0; fed < total_samples; ) {
                size_t n = total_samples - fed; if (n > block) n = block;
                for (size_t i = 0; i < n; ++i) {
                    double ci = cos(phase) * amp;
                    double si = sin(phase) * amp;
                    if (ci >  127.0) ci =  127.0; else if (ci < -128.0) ci = -128.0;
                    if (si >  127.0) si =  127.0; else if (si < -128.0) si = -128.0;
                    buf[2*i]     = (int8_t)ci;
                    buf[2*i + 1] = (int8_t)si;
                    phase += phase_inc;
                }
                channelizer_process_int8(c, buf, n);
                fed += n;
            }
            free(buf);

            /* Find the peak bin in this run for relative-power reference. */
            double max_db = -200.0;
            for (int k = 0; k < n_fit; ++k) {
                double avg = stats[k].nsamples
                    ? stats[k].power_sum / (double)stats[k].nsamples
                    : 0.0;
                double db = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
                if (db > max_db) max_db = db;
            }
            for (int leak_off = -leak_window; leak_off <= leak_window; ++leak_off) {
                int k = src_idx + leak_off;
                if (k < 0 || k >= n_fit) continue;
                double avg = stats[k].nsamples
                    ? stats[k].power_sum / (double)stats[k].nsamples
                    : 0.0;
                double db = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
                double rel = db - max_db;
                fprintf(csv, "%u,%d,%d,%.4f,%+d,%.3f,%+.3f\n",
                        fs, bw_hz, src_slot, offset_frac[o], leak_off, db, rel);
            }
            channelizer_destroy(c);
            free(stats);
        }
        free(fit);
    }
    fclose(csv);
    fprintf(stderr,
            "selftest-rejection-offbin: at half-bin offset (delta=0.5*BW), the source's energy\n"
            "  appears equally in two adjacent grid bins; an off-grid emitter halfway between\n"
            "  channel centers therefore lights up two channels simultaneously, not one.\n"
            "  Inspect the CSV for absolute and relative power at each (offset, leak_offset)\n"
            "  point and tune scanner thresholds accordingly.\n"
            "  CSV: %s\n", csvpath);
    return 0;
}

/* ---- Wideband-noise processing-gain sweep -----------------------------
 *
 * Inject cs8 AWGN (and optionally a CW tone added to it) at the channelizer
 * input. Measure target-bin noise power both alone and combined with the
 * tone; derive output SNR and compare to the input full-band SNR. For an
 * FFT-based decimator-by-M the per-bin noise bandwidth shrinks by ~M, so
 * the per-bin output SNR exceeds the full-band input SNR by ~10*log10(M)
 * (modulo the prototype filter's ENBW, which we don't analytically
 * subtract here -- a small constant residual is expected).
 *
 * The signal-power estimate uses a two-pass form to avoid biasing the noise estimate: signal = max(target_with_tone - target_noise_only, eps).
 * Off-source bins are written to the CSV as diagnostics only, not used
 * in the primary SNR calculation, because finite-filter leakage biases
 * the noise estimate.
 *
 * Deterministic PRNG seed so the CSV is reproducible across runs.
 */

static uint64_t g_procgain_rng_state = 0x243f6a8885a308d3ULL;

static inline double procgain_uniform(void)
{
    /* xorshift64*; not cryptographically secure but reproducible and fast. */
    uint64_t s = g_procgain_rng_state;
    s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
    g_procgain_rng_state = s;
    uint64_t r = s * 2685821657736338717ULL;
    /* Map upper 53 bits to (0, 1) -- excludes 0 to be safe for log(). */
    double u = (double)((r >> 11) | 1) / (double)((uint64_t)1 << 53);
    return u;
}

static inline void procgain_box_muller(double *z0, double *z1)
{
    double u1 = procgain_uniform();
    double u2 = procgain_uniform();
    double r  = sqrt(-2.0 * log(u1));
    double th = 2.0 * M_PI * u2;
    *z0 = r * cos(th);
    *z1 = r * sin(th);
}

/* Run the channelizer once at this (BW, source, noise_sigma_lsb,
 * tone_amp_lsb) configuration. Returns per-sink mean power in
 * dBFS (relative to full-scale ±1 after the cs8 -> float scale by
 * 1/127). out_power_dbfs[] is sized to n_fit; clip_fraction reports
 * how many input cs8 samples saturated. */
static int procgain_run_once(uint64_t f_center, uint32_t fs, int bw_hz,
                             int n_fit, const int *fit,
                             uint64_t f_tone, double tone_amp_lsb,
                             double noise_sigma_lsb,
                             double *out_power_dbfs,
                             double *out_clip_fraction)
{
    channelizer_t *c = channelizer_create(f_center, fs);
    if (!c) return -1;
    chan_stats_t *stats = calloc((size_t)n_fit, sizeof(*stats));
    if (!stats) { channelizer_destroy(c); return -1; }
    for (int k = 0; k < n_fit; ++k) {
        channel_cfg_t cfg = {
            .f_hz = mesh_channel_freq_hz(mesh_lookup_region(opt_region ? opt_region : "US"),
                                          bw_hz, fit[k]),
            .bw_hz = bw_hz, .sf = 7, .cr = 5,
            .on_baseband = selftest_cb, .user = stats,
        };
        channelizer_add_channel(c, &cfg);
    }

    double phase = 0.0;
    double phase_inc = 2.0 * M_PI
        * (double)((int64_t)f_tone - (int64_t)f_center) / (double)fs;
    size_t total_samples = fs / 10;
    const size_t block = 65536;
    int8_t *buf = malloc(block * 2);
    if (!buf) { channelizer_destroy(c); free(stats); return -1; }
    uint64_t clips = 0;
    for (size_t fed = 0; fed < total_samples; ) {
        size_t n = total_samples - fed; if (n > block) n = block;
        for (size_t i = 0; i < n; ++i) {
            double ni, nq;
            procgain_box_muller(&ni, &nq);
            double ci = tone_amp_lsb * cos(phase) + noise_sigma_lsb * ni;
            double si = tone_amp_lsb * sin(phase) + noise_sigma_lsb * nq;
            phase += phase_inc;
            if (ci >  127.0) { ci =  127.0; ++clips; }
            else if (ci < -128.0) { ci = -128.0; ++clips; }
            if (si >  127.0) { si =  127.0; ++clips; }
            else if (si < -128.0) { si = -128.0; ++clips; }
            buf[2*i]     = (int8_t)ci;
            buf[2*i + 1] = (int8_t)si;
        }
        channelizer_process_int8(c, buf, n);
        fed += n;
    }
    free(buf);

    for (int k = 0; k < n_fit; ++k) {
        double avg = stats[k].nsamples
            ? stats[k].power_sum / (double)stats[k].nsamples
            : 0.0;
        out_power_dbfs[k] = avg > 0.0 ? 10.0 * log10(avg) : -200.0;
    }
    if (out_clip_fraction) {
        /* 2 lanes per IQ sample -> 2 * total_samples comparisons. */
        *out_clip_fraction = (double)clips / (2.0 * (double)total_samples);
    }
    channelizer_destroy(c);
    free(stats);
    return 0;
}

int run_selftest_rejection_procgain(void)
{
    const char *region_name = opt_region ? opt_region : "US";
    const mesh_region_t *r = mesh_lookup_region(region_name);
    if (!r) {
        fprintf(stderr, "selftest-rejection-procgain: unknown region '%s'\n", region_name);
        return 1;
    }
    uint32_t fs = samp_rate > 0.0 ? (uint32_t)samp_rate : 20000000u;
    uint64_t f_center = center_freq > 0.0
        ? (uint64_t)center_freq
        : (uint64_t)((r->f_lo_mhz + r->f_hi_mhz) * 0.5 * 1e6);

    int bw_set[8] = {0}; int n_bw = 0;
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        int bw = r->wide_lora ? MESH_PRESETS[p].bw_hz_wide
                              : MESH_PRESETS[p].bw_hz_narrow;
        int seen = 0;
        for (int i = 0; i < n_bw; ++i) if (bw_set[i] == bw) { seen = 1; break; }
        if (!seen && n_bw < (int)(sizeof(bw_set)/sizeof(bw_set[0])))
            bw_set[n_bw++] = bw;
    }
    for (int i = 0; i < n_bw; ++i)
        for (int j = i + 1; j < n_bw; ++j)
            if (bw_set[j] < bw_set[i]) { int t = bw_set[i]; bw_set[i] = bw_set[j]; bw_set[j] = t; }

    /* Sweeps. */
    static const double noise_sigmas_lsb[] = { 0.5, 1.0, 2.0, 3.0 };
    static const double input_snrs_db[]    = { -10.0, 0.0, 10.0, 20.0 };
    const int n_sigmas = (int)(sizeof(noise_sigmas_lsb) / sizeof(noise_sigmas_lsb[0]));
    const int n_snrs   = (int)(sizeof(input_snrs_db) / sizeof(input_snrs_db[0]));

    char ts[32], csvpath[256];
    time_t now = time(NULL); struct tm tmv; gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
    snprintf(csvpath, sizeof(csvpath),
             "/tmp/meshtastic-pfb-rejection-procgain-%s.csv", ts);
    FILE *csv = fopen(csvpath, "w");
    if (!csv) {
        fprintf(stderr, "selftest-rejection-procgain: cannot open %s: %s\n",
                csvpath, strerror(errno));
        return 1;
    }
    fprintf(csv,
            "rate_hz,bw_hz,M,source_ch,noise_sigma_lsb,input_snr_db,tone_amp_dbfs,"
            "input_noise_dbfs,target_noise_only_dbfs,target_tone_noise_dbfs,"
            "output_snr_db,processing_gain_db,expected_gain_db,gain_residual_db,"
            "median_offbin_noise_dbfs,worst_offbin_noise_dbfs,clip_fraction\n");

    fprintf(stderr,
            "selftest-rejection-procgain: region=%s center=%.3f MHz rate=%u sps\n"
            "selftest-rejection-procgain: noise sigmas (LSB): ", r->name, f_center / 1e6, fs);
    for (int s = 0; s < n_sigmas; ++s) fprintf(stderr, "%.1f%s", noise_sigmas_lsb[s], s + 1 < n_sigmas ? ", " : "");
    fprintf(stderr, "\nselftest-rejection-procgain: input full-band SNRs (dB): ");
    for (int s = 0; s < n_snrs; ++s) fprintf(stderr, "%+.1f%s", input_snrs_db[s], s + 1 < n_snrs ? ", " : "");
    fprintf(stderr, "\nselftest-rejection-procgain: writing %s\n", csvpath);

    double rf_lo = (double)f_center - 0.5 * (double)fs;
    double rf_hi = (double)f_center + 0.5 * (double)fs;

    /* Track per-BW median gain residual for the summary. */
    typedef struct { int bw; int M; int n_meas; double sum_gain; double sum_residual;
                     double worst_residual; int worst_snr_idx; int worst_sigma_idx; } bw_summary_t;
    bw_summary_t *bws = calloc((size_t)n_bw, sizeof(*bws));
    if (!bws) { fclose(csv); return 1; }
    for (int g = 0; g < n_bw; ++g) { bws[g].bw = bw_set[g]; }

    double max_clip = 0.0;
    g_procgain_rng_state = 0x243f6a8885a308d3ULL;  /* reset for determinism */

    for (int g = 0; g < n_bw; ++g) {
        int bw_hz = bw_set[g];
        if (fs % (uint32_t)bw_hz != 0) continue;
        int n_slots = mesh_channel_count(r, bw_hz);
        int *fit = malloc(sizeof(int) * (size_t)(n_slots > 0 ? n_slots : 1));
        if (!fit) { fclose(csv); free(bws); return 1; }
        int n_fit = 0;
        for (int s = 0; s < n_slots; ++s) {
            double f = (double)mesh_channel_freq_hz(r, bw_hz, s);
            if (f >= rf_lo && f <= rf_hi) fit[n_fit++] = s;
        }
        if (n_fit < 2) { free(fit); continue; }
        int M = (int)(fs / (uint32_t)bw_hz);
        bws[g].M = M;
        double expected_gain_db = 10.0 * log10((double)M);

        int src_idx  = n_fit / 2;
        int src_slot = fit[src_idx];
        uint64_t f_tone = mesh_channel_freq_hz(r, bw_hz, src_slot);

        fprintf(stderr,
                "selftest-rejection-procgain:  BW=%d kHz  M=%d  10*log10(M)=%.2f dB  source=slot%d\n",
                bw_hz / 1000, M, expected_gain_db, src_slot);

        double *powers = malloc(sizeof(double) * (size_t)n_fit);
        if (!powers) { free(fit); fclose(csv); free(bws); return 1; }

        for (int si = 0; si < n_sigmas; ++si) {
            double sigma_lsb = noise_sigmas_lsb[si];

            /* Noise-only run for this sigma. Used as the target-bin noise
             * reference for every (SNR) at this sigma. */
            double clipfrac_noise = 0.0;
            if (procgain_run_once(f_center, fs, bw_hz, n_fit, fit,
                                   f_tone, 0.0, sigma_lsb,
                                   powers, &clipfrac_noise) < 0) {
                free(powers); free(fit); fclose(csv); free(bws); return 1;
            }
            double target_noise_only = powers[src_idx];

            /* Median + worst off-bin noise diagnostics. */
            double *off = malloc(sizeof(double) * (size_t)(n_fit - 1));
            int n_off = 0;
            for (int k = 0; k < n_fit; ++k) if (k != src_idx) off[n_off++] = powers[k];
            qsort(off, (size_t)n_off, sizeof(double), double_cmp);
            double median_offbin = off[n_off / 2];
            double worst_offbin  = off[n_off - 1];
            free(off);

            /* Analytic noise power on input: complex AWGN with per-component
             * sigma (in LSB units), scaled by 1/127 by the cs8 ingest path
             * before the channelizer sees it. E[|x|^2] = 2*(sigma/127)^2. */
            double sigma_float = sigma_lsb / 127.0;
            double input_noise_pw = 2.0 * sigma_float * sigma_float;
            double input_noise_dbfs = 10.0 * log10(input_noise_pw);

            for (int sni = 0; sni < n_snrs; ++sni) {
                double snr_db = input_snrs_db[sni];

                /* Tone power needed for this full-band SNR vs the noise power.
                 * CW with peak amplitude A on each of I and Q (cos/sin) has
                 * E[|x|^2] = A^2; in LSB units, A^2_lsb. So tone_amp_lsb
                 * follows from: 10*log10(A^2 / input_noise_pw) = snr_db. */
                double tone_pw_float = input_noise_pw * pow(10.0, snr_db / 10.0);
                double tone_amp_float = sqrt(tone_pw_float);
                double tone_amp_lsb = tone_amp_float * 127.0;
                double tone_amp_dbfs = 10.0 * log10(tone_pw_float);

                /* Skip if combined would clip too often. Rough budget:
                 * tone peak excursion ±A, noise 3-sigma ±3*sigma. */
                double peak = tone_amp_lsb + 3.0 * sigma_lsb;
                if (peak > 124.0) {
                    fprintf(stderr,
                            "  sigma=%.1f LSB  in_SNR=%+.1f dB:  SKIP (would clip; peak ≈ %.0f LSB)\n",
                            sigma_lsb, snr_db, peak);
                    continue;
                }

                double clipfrac_run = 0.0;
                if (procgain_run_once(f_center, fs, bw_hz, n_fit, fit,
                                       f_tone, tone_amp_lsb, sigma_lsb,
                                       powers, &clipfrac_run) < 0) {
                    free(powers); free(fit); fclose(csv); free(bws); return 1;
                }
                if (clipfrac_run > max_clip) max_clip = clipfrac_run;
                double target_tone_noise = powers[src_idx];

                /* Output signal power = excess over noise-only.
                 * powers are in dB; convert to linear before subtracting. */
                double tn_lin = pow(10.0, target_tone_noise / 10.0);
                double no_lin = pow(10.0, target_noise_only / 10.0);
                double sig_lin = tn_lin - no_lin;
                if (sig_lin < 1e-30) sig_lin = 1e-30;
                double output_snr_db = 10.0 * log10(sig_lin / no_lin);
                double proc_gain = output_snr_db - snr_db;
                double residual  = proc_gain - expected_gain_db;

                fprintf(csv,
                        "%u,%d,%d,%d,%.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%+.3f,%.5f\n",
                        fs, bw_hz, M, src_slot, sigma_lsb, snr_db, tone_amp_dbfs,
                        input_noise_dbfs, target_noise_only, target_tone_noise,
                        output_snr_db, proc_gain, expected_gain_db, residual,
                        median_offbin, worst_offbin, clipfrac_run);

                /* Accumulate only sigma >= 1 LSB rows for the CI gate;
                 * sigma=0.5 LSB is below the cs8 quantization step and
                 * has unreliable noise statistics. The sigma<1 rows still
                 * print to stderr and land in the CSV. */
                int gate_eligible = (sigma_lsb >= 1.0);
                if (gate_eligible) {
                    int first = (bws[g].n_meas == 0);
                    bws[g].n_meas++;
                    bws[g].sum_gain     += proc_gain;
                    bws[g].sum_residual += residual;
                    if (first || fabs(residual) > fabs(bws[g].worst_residual)) {
                        bws[g].worst_residual = residual;
                        bws[g].worst_snr_idx = sni;
                        bws[g].worst_sigma_idx = si;
                    }
                }

                fprintf(stderr,
                        "  sigma=%.1f LSB  in_SNR=%+5.1f dB  out_SNR=%+6.2f dB  gain=%+5.2f dB  resid=%+5.2f dB\n",
                        sigma_lsb, snr_db, output_snr_db, proc_gain, residual);
            }
        }
        free(powers);
        free(fit);
    }
    fclose(csv);

    fprintf(stderr,
            "selftest-rejection-procgain: summary (mean processing gain vs 10*log10(M)):\n");
    for (int g = 0; g < n_bw; ++g) {
        if (bws[g].n_meas == 0) continue;
        double mean_gain = bws[g].sum_gain     / (double)bws[g].n_meas;
        double mean_res  = bws[g].sum_residual / (double)bws[g].n_meas;
        double expected  = 10.0 * log10((double)bws[g].M);
        fprintf(stderr,
                "  BW=%4d kHz M=%-3d  expected %5.2f dB  measured mean %5.2f dB  residual mean %+5.2f dB  worst %+5.2f dB\n",
                bws[g].bw / 1000, bws[g].M, expected, mean_gain, mean_res, bws[g].worst_residual);
    }
    fprintf(stderr, "selftest-rejection-procgain: max clip fraction observed = %.5f\n", max_clip);
    fprintf(stderr,
            "selftest-rejection-procgain: note: sigma=0.5 LSB rows are below the cs8 quantization\n"
            "  step and excluded from the regression gate; sigma >= 1.0 LSB rows show the\n"
            "  stable measurement and feed the gate below.\n");
    fprintf(stderr, "selftest-rejection-procgain: CSV: %s\n", csvpath);

    /* CI gate: per-BW mean processing-gain residual (sigma >= 1 LSB only)
     * must stay within +/- 4 dB of 10*log10(M). Measured is ~+1 dB across
     * all three BW groups; 4 dB catches a structural break without firing
     * on measurement noise or the small window-related residual we already
     * understand. */
    const double residual_window_db = 4.0;
    int gate_failed = 0;
    for (int g = 0; g < n_bw; ++g) {
        if (bws[g].n_meas == 0) continue;
        double mean_res = bws[g].sum_residual / (double)bws[g].n_meas;
        if (fabs(mean_res) > residual_window_db) {
            fprintf(stderr,
                    "selftest-rejection-procgain: GATE FAIL  BW=%d kHz  mean residual %+.2f dB outside +/-%.1f dB\n",
                    bws[g].bw / 1000, mean_res, residual_window_db);
            gate_failed = 1;
        }
    }
    fprintf(stderr, "selftest-rejection-procgain: regression gate (per-BW mean residual within +/-%.0f dB): %s\n",
            residual_window_db, gate_failed ? "FAIL" : "PASS");
    free(bws);
    return gate_failed ? 1 : 0;
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

    /* Open IQ-record sink if requested. Pick target byte format from
     * file extension: .cs8 -> int8 I/Q (quantize float to int8 on the
     * fly when SDR native is float); .cf32 or anything else -> native
     * format written raw. Without the .cs8 quantization step, a .cs8
     * file recorded from a float-native SDR (USRP/SoapySDR cf32) was
     * actually fc32 bytes, which replay reads as int8 garbage. */
    if (opt_iq_record) {
        g_iq_record_fp = fopen(opt_iq_record, "wb");
        if (!g_iq_record_fp) {
            fprintf(stderr, "iq-record: cannot open %s for write\n", opt_iq_record);
        } else {
            size_t L = strlen(opt_iq_record);
            g_iq_record_target_cs8 = (L >= 4 && !strcasecmp(opt_iq_record + L - 4, ".cs8"));
            fprintf(stderr, "iq-record: writing %s to %s\n",
                    g_iq_record_target_cs8 ? "cs8 (int8 I/Q)" : "native (raw)",
                    opt_iq_record);
        }
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

    if (sample_pipeline_start() != 0) {
        fprintf(stderr, "sample-pump: failed to start\n");
        feed_shutdown();
        return 1;
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
        sample_pipeline_stop();
        feed_shutdown();
        return 1;
    }

    /* Wait. push_samples() (called from input thread) does the work.
     * Poll instead of pause() to avoid a race where the input thread
     * sets running=0 + delivers SIGINT before we can enter pause(). */
    while (running)
        usleep(100000);

    pthread_join(input_tid, NULL);
    sample_pipeline_stop();
    pthread_join(stats_tid, NULL);
    pthread_join(wd_tid, NULL);

    /* Async PFB sink workers may still hold full or partial baseband
     * buffers after live SDR input stops. Drain them before stopping the
     * dedup drainer or destroying g_demods; file replay already does this
     * at EOF, but live backends need the same quiescence point here. */
    if (g_channelizer) channelizer_flush(g_channelizer);

    /* Stop the dedup drainer last; it flushes any pending clusters
     * before returning so the JSON stream gets the tail. */
    dedup_drainer_stop();

    /* Cleanup */
    if (g_iq_record_fp) {
        fclose(g_iq_record_fp);
        g_iq_record_fp = NULL;
        fprintf(stderr, "iq-record: peak |sample|=%.3f, clip count=%llu samples\n",
                sqrt(g_iq_record_peak_mag2),
                (unsigned long long)g_iq_record_clip);
    }
    web_shutdown();
    feed_shutdown();
    gpsd_shutdown();
    announce_shutdown();
    c2_dealer_shutdown();
    pcap_out_shutdown();
    psk_dict_shutdown();
    archive_shutdown();
    geofence_shutdown();
    if (sample_pump_stats_enabled()) {
        /* Print the demod state-machine summary before tearing down decoders.
         * Critical at-a-glance signal for false-positive sync detection (lots
         * of preamble_locks with ~0 crc_pass) vs the healthy case (steady
         * pyramid down to crc_pass at a sane SNR). */
        lora_demod_stats_dump(stderr);
        /* Dedup Tier-3 outcome counters. _suppressed_near_pass shows the
         * cross-slot phantom rate that the wide-window rule absorbed;
         * _admitted_no_pass shows CRC-fail frames that the feed published
         * because no CRC-pass winner appeared in the window. */
        fprintf(stderr, "[dedup] tier3: crc_fail suppressed_near_pass=%llu admitted_no_pass=%llu\n",
                (unsigned long long)dedup_stat_crc_fail_suppressed_near_pass(),
                (unsigned long long)dedup_stat_crc_fail_admitted_no_pass());
    }
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
    if (rc >= 2 && rc != 100 && rc != 101 && rc != 102 && rc != 103 && rc != 104 && rc != 105) return rc;

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
    if (rc == 101) {              /* --selftest-rejection */
        extern int run_selftest_rejection(void);
        return run_selftest_rejection();
    }
    if (rc == 102) {              /* --selftest-rejection-amplitude */
        extern int run_selftest_rejection_amplitude(void);
        return run_selftest_rejection_amplitude();
    }
    if (rc == 103) {              /* --selftest-rejection-twotone */
        extern int run_selftest_rejection_twotone(void);
        return run_selftest_rejection_twotone();
    }
    if (rc == 104) {              /* --selftest-rejection-offbin */
        extern int run_selftest_rejection_offbin(void);
        return run_selftest_rejection_offbin();
    }
    if (rc == 105) {              /* --selftest-rejection-procgain */
        extern int run_selftest_rejection_procgain(void);
        return run_selftest_rejection_procgain();
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
