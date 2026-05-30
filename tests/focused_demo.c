/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * focused_demo: scan-then-focus Phase 2 prototype.
 *
 * One wideband file reader streams cs8 IQ into N independent focused-decode
 * workers. Each worker has its own DDC chain (NCO mixer + Hamming-windowed
 * LPF + decimate) and its own lora_decoder_t. None of them go through the
 * wideband polyphase channelizer -- this is the architectural primitive
 * the live "stare mode" will use when the cheap scanner triggers a focused
 * decode for a channel that's just shown activity.
 *
 * For this prototype the workers are configured at startup (manual
 * promotion) instead of being driven by live scanner events. The shared
 * reader broadcasts each sample chunk to every worker in turn; in a future
 * iteration the workers will live on their own threads and the reader will
 * push into a raw-IQ ring buffer they can rewind from.
 *
 * Acceptance: replay /tmp/b205_cluster2.cs8 with focus #0 at 906.875 MHz
 * (the known SF9 channel, 4 expected packet IDs) and focus #1 at a decoy
 * 908.125 MHz (no signal expected). Focus 0 must decode 4 distinct packet
 * IDs (matching the prior single-channel result); focus 1 must decode 0.
 *
 * Usage:
 *   focused_demo --file=PATH [--fmt=cs8|cf32] [--rate=HZ] [--center=HZ]
 *                --focus=CH_HZ:BW:SF:CR[:OS] [--focus=... ...]
 *
 * Build via CMake. Reuses lora.c -- no new DSP, only plumbing.
 */

#include "../lora.h"

#include <complex.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Stubs lora.c expects from the rest of the project. */
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose = 0;

#define MAX_FOCUS 32

typedef struct {
    int    idx;
    /* config */
    double channel_hz;
    int    bw_hz;
    int    sf;
    int    cr;
    int    os_factor;
    /* DDC chain (independent per worker) */
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
    /* Stats */
    _Atomic uint64_t samples_in;
    _Atomic uint64_t samples_to_decoder;
    _Atomic uint64_t frames_delivered;
} focused_t;

static focused_t g_focus[MAX_FOCUS];
static int g_n_focus = 0;

/* Per-worker frame callback. user pointer carries the focused_t* so we tag
 * each output line with its focus index. */
static void on_focused_frame(const uint8_t *payload, size_t len,
                             const lora_frame_meta_t *meta, void *user)
{
    focused_t *f = (focused_t *)user;
    atomic_fetch_add(&f->frames_delivered, 1);
    fprintf(stderr,
            "[focus=%d ch=%.3fMHz sf=%d] len=%zu crc_ok=%d snr=%.1fdB",
            f->idx, f->channel_hz / 1e6, f->sf, len,
            meta->payload_crc_ok, (double)meta->snr_db);
    if (len >= 12) {
        fprintf(stderr,
                " from=!%02x%02x%02x%02x packet_id=0x%02x%02x%02x%02x",
                payload[7], payload[6], payload[5], payload[4],
                payload[11], payload[10], payload[9], payload[8]);
    }
    fputc('\n', stderr);
}

/* Hamming-windowed sinc LPF, cutoff at -6 dB. Length is rounded up to odd
 * for linear-phase symmetry. Same shape as test_oversample_self.c's. */
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
    if (sum > 0.0) {
        for (int i = 0; i < n_taps; ++i) taps[i] = (float)(taps[i] / sum);
    }
    return n_taps;
}

/* Parse --focus=CH_HZ:BW:SF:CR[:OS]. Returns 0 on success, -1 on error. */
static int parse_focus_spec(const char *s, focused_t *f)
{
    f->os_factor = 1;
    char tmp[256]; strncpy(tmp, s, sizeof(tmp) - 1); tmp[sizeof(tmp)-1] = 0;
    char *save = NULL;
    char *t = strtok_r(tmp, ":", &save); if (!t) return -1;
    f->channel_hz = atof(t);
    t = strtok_r(NULL, ":", &save); if (!t) return -1; f->bw_hz = atoi(t);
    t = strtok_r(NULL, ":", &save); if (!t) return -1; f->sf = atoi(t);
    t = strtok_r(NULL, ":", &save); if (!t) return -1; f->cr = atoi(t);
    t = strtok_r(NULL, ":", &save); if (t) f->os_factor = atoi(t);
    if (f->bw_hz <= 0 || f->sf < 7 || f->sf > 12 || f->cr < 5 || f->cr > 8
        || f->os_factor < 1 || f->os_factor > 4) return -1;
    return 0;
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s --file=PATH [--fmt=cs8|cf32] [--rate=HZ] [--center=HZ]\n"
        "          --focus=CH_HZ:BW:SF:CR[:OS] [--focus=... ...]\n"
        "  --file=PATH     wideband IQ capture (cs8 or cf32)\n"
        "  --fmt=cs8|cf32  (default cs8)\n"
        "  --rate=HZ       capture sample rate (default 20000000)\n"
        "  --center=HZ     capture center freq (default 915000000)\n"
        "  --focus=...     repeat to register multiple focused workers\n"
        "                  CH_HZ = channel center, BW in Hz, SF 7-12, CR 5-8,\n"
        "                  OS optional 1/2/4 (default 1)\n"
        "  --ntaps=N       LPF length for each focused DDC (default 257)\n"
        "  --duration=S    cap replay to S seconds (default: whole file)\n",
        a0);
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *fmt  = "cs8";
    double samp_rate = 20e6;
    double center_hz = 915e6;
    int    n_taps    = 257;
    double duration_s = 0.0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strncmp(a, "--file=",     7)) path = a + 7;
        else if (!strncmp(a, "--fmt=",      6)) fmt  = a + 6;
        else if (!strncmp(a, "--rate=",     7)) samp_rate = atof(a + 7);
        else if (!strncmp(a, "--center=",   9)) center_hz = atof(a + 9);
        else if (!strncmp(a, "--ntaps=",    8)) n_taps = atoi(a + 8);
        else if (!strncmp(a, "--duration=",11)) duration_s = atof(a + 11);
        else if (!strncmp(a, "--focus=",    8)) {
            if (g_n_focus >= MAX_FOCUS) {
                fprintf(stderr, "too many --focus (max %d)\n", MAX_FOCUS);
                return 2;
            }
            g_focus[g_n_focus].idx = g_n_focus;
            if (parse_focus_spec(a + 8, &g_focus[g_n_focus]) != 0) {
                fprintf(stderr, "bad --focus spec: %s\n", a + 8);
                return 2;
            }
            ++g_n_focus;
        }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }
    if (!path || g_n_focus == 0) { usage(argv[0]); return 2; }
    int fmt_cf32 = !strcmp(fmt, "cf32");

    /* Initialise each focused worker: DDC chain + decoder. */
    for (int k = 0; k < g_n_focus; ++k) {
        focused_t *f = &g_focus[k];
        double freq_offset = f->channel_hz - center_hz;
        f->mix_inc   = -2.0 * M_PI * freq_offset / samp_rate;
        f->mix_phase = 0.0;
        f->decim     = (int)(samp_rate / (double)(f->os_factor * f->bw_hz) + 0.5);
        if (f->decim <= 0) {
            fprintf(stderr, "focus %d: decim<=0 (rate=%.0f, os*bw=%d)\n",
                    k, samp_rate, f->os_factor * f->bw_hz);
            return 1;
        }
        f->channel_rate = samp_rate / (double)f->decim;
        f->decim_phase  = 0;
        /* LPF: cutoff at channel BW/2 (Hamming, n_taps). Same as
         * test_oversample_self -- room to lengthen later for os>1. */
        f->n_taps = n_taps;
        f->taps   = malloc(sizeof(float) * (size_t)f->n_taps);
        if (!f->taps) { perror("taps"); return 1; }
        f->n_taps = build_lpf(f->n_taps, samp_rate,
                              (double)f->bw_hz * 0.5, f->taps);
        f->delay  = calloc((size_t)f->n_taps, sizeof(float complex));
        f->delay_head = 0;
        if (!f->delay) { perror("delay"); return 1; }
        f->dec = lora_decoder_create_os(f->sf, f->cr, f->bw_hz, f->os_factor);
        if (!f->dec) {
            fprintf(stderr, "focus %d: lora_decoder_create_os failed\n", k);
            return 1;
        }
        lora_decoder_set_callback(f->dec, on_focused_frame, f);
        lora_decoder_set_center_freq(f->dec, f->channel_hz);
        fprintf(stderr,
                "focus %d: ch=%.3fMHz BW=%dkHz SF=%d CR=4/%d os=%d  "
                "decim=%d -> %.0f sps  ntaps=%d\n",
                k, f->channel_hz / 1e6, f->bw_hz / 1000, f->sf, f->cr,
                f->os_factor, f->decim, f->channel_rate, f->n_taps);
    }

    /* Shared reader loop. Each input sample is dispatched to every focused
     * worker, which advances its own mixer / FIR / decimator state and (on
     * decimation phase) emits one decimated sample into its lora decoder. */
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("open"); return 1; }
    const size_t CHUNK = 65536;
    int8_t *raw_cs8  = NULL;
    float  *raw_cf32 = NULL;
    if (fmt_cf32) raw_cf32 = malloc(sizeof(float) * 2 * CHUNK);
    else          raw_cs8  = malloc(2 * CHUNK);
    if ((!raw_cs8 && !raw_cf32)) { fclose(fp); return 1; }
    size_t in_sample_bytes = fmt_cf32 ? (2 * sizeof(float)) : 2;
    uint64_t total_in_samps = 0;
    uint64_t budget = (duration_s > 0.0)
                      ? (uint64_t)(samp_rate * duration_s)
                      : (uint64_t)-1;

    /* Per-worker scratch for one decimated sample (avoid alloc-in-loop). */
    while (total_in_samps < budget) {
        size_t want = CHUNK;
        if (total_in_samps + want > budget) want = budget - total_in_samps;
        void *buf = fmt_cf32 ? (void *)raw_cf32 : (void *)raw_cs8;
        size_t got_bytes = fread(buf, 1, in_sample_bytes * want, fp);
        if (got_bytes < in_sample_bytes) break;
        size_t got = got_bytes / in_sample_bytes;
        for (size_t i = 0; i < got; ++i) {
            float ii, qq;
            if (fmt_cf32) {
                ii = raw_cf32[2*i+0];
                qq = raw_cf32[2*i+1];
            } else {
                ii = (float)raw_cs8[2*i+0];
                qq = (float)raw_cs8[2*i+1];
            }
            float complex x = ii + I * qq;
            /* Dispatch to every focused worker. */
            for (int k = 0; k < g_n_focus; ++k) {
                focused_t *f = &g_focus[k];
                atomic_fetch_add(&f->samples_in, 1);
                /* Mix to baseband. */
                float complex rot = (float complex)(cos(f->mix_phase) + I * sin(f->mix_phase));
                float complex mixed = x * rot;
                f->mix_phase += f->mix_inc;
                if (f->mix_phase >  M_PI) f->mix_phase -= 2.0 * M_PI;
                if (f->mix_phase < -M_PI) f->mix_phase += 2.0 * M_PI;
                /* FIR: push into circular delay, then convolve when
                 * decimation phase wraps. */
                f->delay[f->delay_head] = mixed;
                f->delay_head = (f->delay_head + 1) % f->n_taps;
                if (++f->decim_phase >= f->decim) {
                    f->decim_phase = 0;
                    /* Convolve. taps[] is symmetric / linear-phase but we
                     * still do the straight dot product -- prototype. */
                    float complex acc = 0.0f + 0.0f * I;
                    int idx = f->delay_head; /* oldest sample */
                    for (int t = 0; t < f->n_taps; ++t) {
                        acc += f->delay[idx] * f->taps[t];
                        idx = (idx + 1) % f->n_taps;
                    }
                    /* Feed one decimated sample into this worker's decoder. */
                    lora_decoder_feed(f->dec, &acc, 1);
                    atomic_fetch_add(&f->samples_to_decoder, 1);
                }
            }
        }
        total_in_samps += got;
    }
    fclose(fp);
    free(raw_cs8); free(raw_cf32);

    fprintf(stderr, "\nfocused_demo: read %llu input samples (%.2f s)\n",
            (unsigned long long)total_in_samps,
            (double)total_in_samps / samp_rate);
    for (int k = 0; k < g_n_focus; ++k) {
        focused_t *f = &g_focus[k];
        fprintf(stderr,
                "focus %d: ch=%.3fMHz  frames=%llu  decim_out=%llu samples\n",
                f->idx, f->channel_hz / 1e6,
                (unsigned long long)atomic_load(&f->frames_delivered),
                (unsigned long long)atomic_load(&f->samples_to_decoder));
        lora_decoder_destroy(f->dec);
        free(f->taps);
        free(f->delay);
    }
    return 0;
}
