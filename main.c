/*
 * meshtastic-sniffer: wideband Meshtastic LoRa receiver.
 *
 * Captures a single wide IQ slice from one SDR, channelizes into every
 * configured Meshtastic preset/channel, runs a LoRa CSS demod per
 * channel, and -- with keys supplied -- AES-CTR decrypts and decodes
 * the inner protobuf payload (text, position, nodeinfo, telemetry,
 * routing, traceroute, neighborinfo, waypoint, admin, etc.) in
 * parallel.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "channelizer.h"
#include "feed.h"
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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

static void on_mesh_event(const mesh_event_t *ev, void *user) {
    intptr_t channel_id = (intptr_t)user;
    if (ev->decrypted) {
        __atomic_add_fetch(&g_decrypts_total, 1, __ATOMIC_RELAXED);
        if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS)
            __atomic_add_fetch(&g_chan_stats[channel_id].decrypted, 1, __ATOMIC_RELAXED);
    }
    feed_publish_event(ev);
}

static void on_lora_frame(const uint8_t *payload, size_t payload_len,
                          const lora_frame_meta_t *meta, void *user)
{
    intptr_t channel_id = (intptr_t)user;
    __atomic_add_fetch(&g_frames_total, 1, __ATOMIC_RELAXED);
    if (channel_id >= 0 && channel_id < CHANNELIZER_MAX_CHANNELS) {
        __atomic_add_fetch(&g_chan_stats[channel_id].frames, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_chan_stats[channel_id].bytes, payload_len, __ATOMIC_RELAXED);
        if (meta) {
            /* Non-atomic float update -- imprecise but fine for stats. */
            g_chan_stats[channel_id].snr_db_sum += (double)meta->snr_db;
            g_chan_stats[channel_id].snr_db_count++;
        }
    }
    float rssi = meta ? meta->rssi_db : 0.0f;
    float snr  = meta ? meta->snr_db  : 0.0f;
    mesh_packet_decode_with_meta(payload, payload_len, rssi, snr,
                                 g_keys, on_mesh_event, user);
}

/* Forward decl for the web SSE publisher (we don't include web.h here
 * to avoid a circular dep when only main needs to push raw lines). */
extern void web_publish_line(const char *json, size_t len);

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

/* Heartbeat thread: stderr stats every 5s + (when --web-spectrum) a 1s
 * spectrum snapshot pushed to the web SSE stream. */
static void *stats_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "stats");
#endif
    static float spectrum_buf[16384];
    uint64_t prev_samples = 0;
    int      stats_counter = 0;
    while (running) {
        for (int i = 0; i < 10 && running; ++i) usleep(100000); /* 1s, interruptible */
        if (!running) break;

        /* Spectrum snapshot every iteration when scanner present + --web-spectrum on. */
        if (g_scanner && opt_web_spectrum && opt_web_port > 0) {
            int N = scanner_snapshot(g_scanner, spectrum_buf, (int)(sizeof(spectrum_buf)/sizeof(float)));
            if (N > 0) {
                /* Downsample to 256 bins by max within each block so we keep peaks. */
                const int OUT = 256;
                float bins[OUT]; for (int b = 0; b < OUT; ++b) bins[b] = 0.0f;
                int per = N / OUT;
                if (per > 0) {
                    for (int b = 0; b < OUT; ++b) {
                        float m = 0.0f;
                        for (int k = 0; k < per; ++k) {
                            float v = spectrum_buf[b * per + k];
                            if (v > m) m = v;
                        }
                        bins[b] = m;
                    }
                    /* Encode as JSON dB. */
                    char line[8192];
                    int n = snprintf(line, sizeof(line),
                        "{\"event\":\"SPECTRUM\",\"f_center\":%.0f,\"samp_rate\":%.0f,\"bins\":[",
                        center_freq, samp_rate);
                    for (int b = 0; b < OUT && n + 12 < (int)sizeof(line); ++b) {
                        double db = bins[b] > 0.0f ? 10.0 * log10((double)bins[b]) : -120.0;
                        n += snprintf(line + n, sizeof(line) - n,
                                      "%s%.1f", b ? "," : "", db);
                    }
                    n += snprintf(line + n, sizeof(line) - n, "]}\n");
                    if (n > 0) web_publish_line(line, (size_t)n);
                }
            }
        }

        /* 5s stderr stats + optional per-channel JSON. */
        if (++stats_counter >= 5) {
            stats_counter = 0;
            uint64_t s   = __atomic_load_n(&g_samples_total,  __ATOMIC_RELAXED);
            uint64_t f   = __atomic_load_n(&g_frames_total,   __ATOMIC_RELAXED);
            uint64_t d   = __atomic_load_n(&g_decrypts_total, __ATOMIC_RELAXED);
            uint64_t og  = __atomic_load_n(&g_offgrid_total,  __ATOMIC_RELAXED);
            double rate_msps = (double)(s - prev_samples) / 5.0e6;
            prev_samples = s;
            fprintf(stderr, "[stats] %.2f Msps in, %llu LoRa frames, %llu decrypted, %llu off-grid hits\n",
                    rate_msps, (unsigned long long)f, (unsigned long long)d,
                    (unsigned long long)og);

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
                        fprintf(sf, "%s{\"id\":%d,\"frames\":%llu,\"decrypted\":%llu,"
                                    "\"avg_snr_db\":%.2f,\"bytes\":%llu}",
                                i ? "," : "", i,
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

    channel_cfg_t cfg = {
        .f_hz        = f_hz,
        .bw_hz       = bw_hz,
        .sf          = sf,
        .cr          = cr,
        .on_baseband = on_channel_baseband,
        .user        = NULL,
    };
    int id = channelizer_add_channel(g_channelizer, &cfg);
    if (id < 0) return -1;

    g_demods[id] = lora_decoder_create(sf, cr, bw_hz);
    if (!g_demods[id]) return -1;
    /* Stash channel id in user pointer so on_lora_frame can attribute stats. */
    lora_decoder_set_callback(g_demods[id], on_lora_frame, (void *)(intptr_t)id);

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
    case SDR_BACKEND_RTLSDR:   return  2400000;   /* R820T2 max */
    case SDR_BACKEND_SOAPYSDR: return  2400000;   /* assume RTL-class via Soapy */
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
        return 1;
    }
    if (n > 0)
        fprintf(stderr, "configured %d channel(s) total.\n", n);

    /* Scanner instance for --scan, --scan-and-decode, --alert-off-grid,
     * or --web-spectrum (the dashboard pulls FFT snapshots from it). */
    if (opt_op_mode != OP_MODE_DECODE || opt_alert_off_grid || opt_web_spectrum) {
        g_scanner = scanner_create((uint64_t)center_freq, (uint32_t)samp_rate, 4096);
        if (g_scanner) {
            scanner_set_known_grid(g_scanner, g_grid_freqs, g_grid_bws, g_grid_count);
            scanner_set_callback(g_scanner, on_off_grid_discovery, NULL);
            fprintf(stderr, "scanner: enabled (4096-bin FFT, excluding %d grid channels)\n",
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
    if (opt_web_port > 0) {
        web_init(opt_web_port);
        /* Make this visible on stdout (not just stderr) so users
         * launching from a GUI / through `tee` etc. see it. */
        fprintf(stdout, "Open http://localhost:%d to see decoded packets, edit keys, see spectrum.\n",
                opt_web_port);
        fflush(stdout);
    } else {
        fprintf(stderr,
          "(no dashboard. add --web=8888 for a Leaflet map + Config tab + spectrum waterfall.)\n");
    }

    /* 5s stats heartbeat thread + 2s/30s friendly watchdogs. */
    pthread_t stats_tid, wd_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);
    pthread_create(&wd_tid,    NULL, watchdog_thread, NULL);

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

    /* Cleanup */
    if (g_iq_record_fp) { fclose(g_iq_record_fp); g_iq_record_fp = NULL; }
    web_shutdown();
    feed_shutdown();
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
