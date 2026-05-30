/*
 * meshtastic-sniffer: PFB per-bin absolute power probe.
 *
 * Reads a wideband cs8 IQ capture, fans it out through the same
 * channelizer the live pipeline uses (no LoRa decoder), accumulates
 * sum-of-squares per channel, and dumps RMS power in dB-relative
 * to the peak channel.
 *
 * Purpose: distinguish three possible causes of cross-bin decoder
 * activity seen in tests/pfb_slot_leakage.sh:
 *   (a) PFB indexing / sample-dispatch bug -- many bins within a
 *       few dB of the target (rejection effectively 0)
 *   (b) windowed-FIR sidelobes -- adjacent bins around -40 dB,
 *       far bins below -60 dB (filter working as designed)
 *   (c) insufficient filter for strong nearby TX -- adjacent bins
 *       around -25 to -40 dB, far bins around -40 to -50 dB
 *       (filter mathematically correct but rejection too weak
 *       for the LoRa decoder's preamble-detect threshold)
 *
 * The decoder's preamble admission gates at peak > 2x noise (~6 dB
 * INSIDE the dechirped FFT, not vs absolute RF). In a noiseless
 * synthetic, even -70 dB coherent leakage can produce a strong
 * peak-vs-bin-floor inside the dechirp and lock the state machine.
 * So this probe measures the ACTUAL filter rejection independent
 * of decoder admission policy.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "../channelizer.h"

#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stubs lora.c / channelizer.c expect from the rest of the project. */
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose = 0;

typedef struct {
    int   id;
    double sumsq;
    uint64_t count;
} bin_stats_t;

static bin_stats_t g_stats[CHANNELIZER_MAX_CHANNELS];

/* Diagnostic: dump the first N complex output samples per channel so we can
 * inspect the PFB output's PHASE PROGRESSION (not just its RMS) -- the bug
 * we're chasing makes consecutive samples spin rather than sit on a stable
 * baseband. Enabled by --dump-first-n=N; 0 disables. */
static int g_dump_first_n = 0;
static int g_dumped[CHANNELIZER_MAX_CHANNELS];

static void on_baseband(int channel_id, const float complex *iq,
                        size_t n, void *user)
{
    (void)user;
    if (channel_id < 0 || channel_id >= CHANNELIZER_MAX_CHANNELS) return;
    bin_stats_t *st = &g_stats[channel_id];
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) {
        float r = crealf(iq[i]);
        float im = cimagf(iq[i]);
        s += (double)r * r + (double)im * im;
    }
    st->sumsq += s;
    st->count += n;
    if (g_dump_first_n > 0) {
        int remaining = g_dump_first_n - g_dumped[channel_id];
        if (remaining > 0) {
            int dump_now = (int)((size_t)remaining < n ? (size_t)remaining : n);
            for (int i = 0; i < dump_now; ++i) {
                float r = crealf(iq[i]);
                float im = cimagf(iq[i]);
                float mag = sqrtf(r * r + im * im);
                float ph  = (mag > 0.0f) ? atan2f(im, r) : 0.0f;
                fprintf(stdout, "ch%d s%d  re=%+0.6f im=%+0.6f  |y|=%0.6f  arg=%+0.4f rad (%+0.1f deg)\n",
                        channel_id, g_dumped[channel_id] + i, r, im, mag,
                        ph, ph * 180.0f / (float)M_PI);
            }
            g_dumped[channel_id] += dump_now;
        }
    }
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s --file=PATH.cs8 [opts]\n"
        "  --file=PATH       wideband cs8 IQ capture (required)\n"
        "  --rate=HZ         capture sample rate (default 20000000)\n"
        "  --center=HZ       capture center freq (default 915000000)\n"
        "  --bw=HZ           channel BW (default 250000)\n"
        "  --slot0-hz=HZ     first channel center (default 905125000)\n"
        "  --nslots=N        how many sequential 250 kHz slots to register\n"
        "                    starting at slot0-hz (default 80)\n", a0);
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    double samp_rate = 20e6;
    double center_hz = 915e6;
    int    bw_hz     = 250000;
    double slot0_hz  = 905125000.0;
    int    nslots    = 80;
    int    os_factor = 1;
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strncmp(a, "--file=",     7)) path        = a + 7;
        else if (!strncmp(a, "--rate=",     7)) samp_rate   = atof(a + 7);
        else if (!strncmp(a, "--center=",   9)) center_hz   = atof(a + 9);
        else if (!strncmp(a, "--bw=",       5)) bw_hz       = atoi(a + 5);
        else if (!strncmp(a, "--slot0-hz=",11)) slot0_hz    = atof(a + 11);
        else if (!strncmp(a, "--nslots=",   9)) nslots      = atoi(a + 9);
        else if (!strncmp(a, "--os=",       5)) os_factor   = atoi(a + 5);
        else if (!strncmp(a, "--dump-first-n=", 15)) g_dump_first_n = atoi(a + 15);
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }
    if (!path) { usage(argv[0]); return 2; }
    if (nslots <= 0 || nslots > CHANNELIZER_MAX_CHANNELS) nslots = 80;

    channelizer_t *c = channelizer_create((uint64_t)center_hz, (uint32_t)samp_rate);
    if (!c) { fprintf(stderr, "channelizer_create failed\n"); return 1; }
    for (int i = 0; i < nslots; ++i) {
        double f = slot0_hz + (double)i * (double)bw_hz;
        channel_cfg_t cfg = {
            .f_hz = (uint64_t)f,
            .bw_hz = bw_hz,
            .sf = 9, .cr = 5, .os_factor = os_factor,
            .on_baseband = on_baseband,
            .user = NULL,
        };
        int id = channelizer_add_channel(c, &cfg);
        if (id < 0) {
            fprintf(stderr, "channelizer_add_channel slot %d (%.3f MHz) failed\n",
                    i, f / 1e6);
            return 1;
        }
        g_stats[id].id = id;
    }
    fprintf(stderr, "added %d channels, BW=%d kHz, slot0=%.3f MHz\n",
            nslots, bw_hz / 1000, slot0_hz / 1e6);

    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return 1; }
    const size_t CHUNK = 65536;
    int8_t *raw = malloc(2 * CHUNK);
    if (!raw) { fclose(f); return 1; }
    uint64_t total = 0;
    while (1) {
        size_t got_bytes = fread(raw, 1, 2 * CHUNK, f);
        if (got_bytes < 2) break;
        size_t got = got_bytes / 2;
        channelizer_process_int8(c, raw, got);
        total += got;
    }
    channelizer_flush(c);
    free(raw);
    fclose(f);
    fprintf(stderr, "processed %llu input samples\n", (unsigned long long)total);

    /* Find peak channel. */
    double peak_rms = 0.0;
    int peak_id = -1;
    for (int i = 0; i < nslots; ++i) {
        if (g_stats[i].count == 0) continue;
        double rms = sqrt(g_stats[i].sumsq / (double)g_stats[i].count);
        if (rms > peak_rms) { peak_rms = rms; peak_id = i; }
    }
    if (peak_id < 0 || peak_rms <= 0) {
        fprintf(stderr, "no channel saw any energy\n");
        channelizer_destroy(c);
        return 1;
    }
    double peak_db = 20.0 * log10(peak_rms);
    fprintf(stderr, "peak channel id=%d  RMS=%.3e  (= 0 dB ref)\n", peak_id, peak_rms);

    /* Dump every channel's RMS relative to peak. */
    printf("# channel_id  rms_abs_db   rms_rel_db_to_peak    samples\n");
    for (int i = 0; i < nslots; ++i) {
        if (g_stats[i].count == 0) {
            printf("  %3d  %20s  %18s  %12llu\n", i, "(no-data)", "(no-data)",
                   (unsigned long long)g_stats[i].count);
            continue;
        }
        double rms = sqrt(g_stats[i].sumsq / (double)g_stats[i].count);
        double abs_db = 20.0 * log10(rms);
        double rel_db = abs_db - peak_db;
        printf("  %3d  %18.3f  %18.3f  %12llu\n",
               i, abs_db, rel_db, (unsigned long long)g_stats[i].count);
    }

    channelizer_destroy(c);
    return 0;
}
