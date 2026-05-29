/*
 * meshtastic-sniffer: oversample self-test.
 *
 * Reads a cs8 IQ capture, digitally tunes to one channel center, low-
 * passes to BW, decimates to (os_factor * BW), and feeds the result to
 * lora_decoder_create_os() at the same os_factor. Prints decoded frames
 * and the demod-stats summary on exit.
 *
 * Purpose: confirm or refute the hypothesis that main.c's critically-
 * sampled PFB path (os_factor=1) loses payload integrity because the
 * symbol grid is misaligned at the sub-sample level. If feeding the
 * decoder at os_factor=4 moves payload_crc_pass off zero on the same
 * /tmp/lf.cs8 file, the wideband path needs an oversampled channel
 * stream too.
 *
 * Build: see CMakeLists.txt rule (test_oversample_self).
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "../lora.h"

#include <complex.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Symbols lora.c expects from the rest of the project. */
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose = 0;

static uint64_t g_frames = 0;

static void on_frame(const uint8_t *payload, size_t len,
                     const lora_frame_meta_t *meta, void *user)
{
    (void)user;
    ++g_frames;
    fprintf(stderr, "[frame] len=%zu has_crc=%d crc_ok=%d snr=%.1fdB",
            len, meta->has_crc, meta->payload_crc_ok, (double)meta->snr_db);
    if (len >= 12) {
        fprintf(stderr, " from=!%02x%02x%02x%02x packet_id=0x%02x%02x%02x%02x",
                payload[7], payload[6], payload[5], payload[4],
                payload[11], payload[10], payload[9], payload[8]);
    }
    fprintf(stderr, "\n");
}

/* Build a windowed-sinc low-pass FIR. cutoff_hz is the -6 dB point.
 * Length is rounded up to odd so the filter is linear-phase symmetric. */
static int build_lpf(int n_taps, double samp_rate, double cutoff_hz,
                     float *taps)
{
    if (n_taps < 21) n_taps = 21;
    if ((n_taps & 1) == 0) n_taps += 1;
    int c = n_taps / 2;
    double wc = 2.0 * M_PI * cutoff_hz / samp_rate;
    double sum = 0.0;
    for (int i = 0; i < n_taps; ++i) {
        int    k = i - c;
        double s = (k == 0) ? wc : sin(wc * k) / k;
        /* Hamming window. */
        double w = 0.54 - 0.46 * cos(2.0 * M_PI * i / (n_taps - 1));
        double t = s * w;
        taps[i] = (float)t;
        sum += t;
    }
    /* Normalize DC gain to 1.0. */
    if (sum > 0.0) {
        for (int i = 0; i < n_taps; ++i) taps[i] = (float)(taps[i] / sum);
    }
    return n_taps;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [opts]\n"
        "  --file=PATH       IQ capture (required)\n"
        "  --fmt=cs8|cf32    input sample format (default cs8)\n"
        "  --rate=HZ         capture sample rate (default 20000000)\n"
        "  --center=HZ       capture center freq (default 915000000)\n"
        "  --channel=HZ      target channel center freq (default 906875000)\n"
        "  --bw=HZ           LoRa channel bandwidth (default 250000)\n"
        "  --sf=N            spreading factor (default 11)\n"
        "  --cr=N            coding rate denom 5..8 (default 5)\n"
        "  --os=N            decoder os_factor (default 4)\n"
        "  --duration=SEC    seconds to process (default 30; 0 = all)\n"
        "  --ntaps=N         LPF taps (default 257)\n"
        "  --no-ddc          skip mixer + decim; assume input is already at\n"
        "                    os * bw, channel at DC. (For synthetic tests.)\n"
        "  --cfo=HZ          inject a carrier-frequency offset at the post-\n"
        "                    DDC rate before feeding the decoder. Used to\n"
        "                    isolate CFO-tracking bugs from clean-IQ bugs.\n"
        "  --no-sfo-inference  skip lora_decoder_set_center_freq() so the\n"
        "                    decoder does NOT derive sfo_hat from measured\n"
        "                    CFO. Use for fixtures that inject pure CFO\n"
        "                    without matching SFO (LO offset, tuning\n"
        "                    offset, synthetic CFO sweeps). Default off:\n"
        "                    matches production where set_center_freq is\n"
        "                    always called and same-crystal SFO inference\n"
        "                    is active.\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *path  = NULL;
    const char *fmt   = "cs8";
    double samp_rate  = 20e6;
    double center_hz  = 915e6;
    double channel_hz = 906.875e6;        /* LongFast slot 0, US 915 MHz center, BW 250 kHz */
    int    bw_hz      = 250000;
    int    sf         = 11;
    int    cr         = 5;
    int    os_factor  = 4;
    double duration_s = 30.0;
    int    n_taps     = 257;
    int    skip_ddc   = 0;
    int    no_sfo_inference = 0;
    double inject_cfo_hz = 0.0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strncmp(a, "--file=",     7)) path        = a + 7;
        else if (!strncmp(a, "--fmt=",      6)) fmt         = a + 6;
        else if (!strncmp(a, "--rate=",     7)) samp_rate   = atof(a + 7);
        else if (!strncmp(a, "--center=",   9)) center_hz   = atof(a + 9);
        else if (!strncmp(a, "--channel=", 10)) channel_hz  = atof(a + 10);
        else if (!strncmp(a, "--bw=",       5)) bw_hz       = atoi(a + 5);
        else if (!strncmp(a, "--sf=",       5)) sf          = atoi(a + 5);
        else if (!strncmp(a, "--cr=",       5)) cr          = atoi(a + 5);
        else if (!strncmp(a, "--os=",       5)) os_factor   = atoi(a + 5);
        else if (!strncmp(a, "--duration=",11)) duration_s  = atof(a + 11);
        else if (!strncmp(a, "--ntaps=",    8)) n_taps      = atoi(a + 8);
        else if (!strcmp (a, "--no-ddc"))       skip_ddc    = 1;
        else if (!strcmp (a, "--no-sfo-inference")) no_sfo_inference = 1;
        else if (!strncmp(a, "--cfo=",      6)) inject_cfo_hz = atof(a + 6);
        else if (!strcmp (a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }
    if (!path) { usage(argv[0]); return 2; }
    int fmt_cf32 = !strcmp(fmt, "cf32");
    if (!fmt_cf32 && strcmp(fmt, "cs8")) {
        fprintf(stderr, "unknown --fmt=%s (cs8 or cf32)\n", fmt); return 2;
    }

    /* Integer decimation from samp_rate down to os_factor * bw. The PFB
     * comment in main.c assumes critical sampling delivers integer-sample
     * symbol alignment; this test forces os_factor*BW so the decoder's
     * own sub-sample STO search has phase choices to pick from. */
    int decim;
    double channel_rate;
    if (skip_ddc) {
        decim         = 1;
        channel_rate  = samp_rate;
        if ((int)samp_rate != os_factor * bw_hz) {
            fprintf(stderr,
                "--no-ddc requires --rate == os * bw (got rate=%.0f, os*bw=%d)\n",
                samp_rate, os_factor * bw_hz);
            return 2;
        }
    } else {
        decim = (int)(samp_rate / (double)(os_factor * bw_hz) + 0.5);
        if (decim <= 0) {
            fprintf(stderr, "decim<=0 (rate=%g, os*bw=%d) -- check args\n",
                    samp_rate, os_factor * bw_hz);
            return 2;
        }
        channel_rate = samp_rate / (double)decim;
    }

    fprintf(stderr,
        "test_oversample_self: file=%s fmt=%s rate=%.0f center=%.0f channel=%.0f "
        "(offset %+.0f Hz) bw=%d sf=%d cr=%d os=%d decim=%d -> %.0f sps "
        "cfo_inject=%+.0f Hz%s\n",
        path, fmt, samp_rate, center_hz, channel_hz,
        channel_hz - center_hz, bw_hz, sf, cr, os_factor, decim, channel_rate,
        inject_cfo_hz, skip_ddc ? " [no-ddc]" : "");

    FILE *f = fopen(path, "rb");
    if (!f) { perror("open cs8"); return 1; }

    lora_decoder_t *dec = lora_decoder_create_os(sf, cr, bw_hz, os_factor);
    if (!dec) { fprintf(stderr, "lora_decoder_create_os failed\n"); fclose(f); return 1; }
    lora_decoder_set_callback(dec, on_frame, NULL);
    /* Match production: main.c:910 calls this when the PFB channelizer
     * assigns a channel. Without it the decoder lazy-allocation of the
     * RCTSL preamble-dechirped buffer is skipped (compute_sto_frac
     * early-returns sto_frac=0) and sfo_hat stays 0 (no SFO inference).
     *
     * --no-sfo-inference opts out for fixtures that inject pure CFO
     * with no matching SFO (LO offset, tuning offset, synthetic CFO
     * sweeps). For those, the same-crystal sfo_hat the decoder would
     * derive from measured CFO is non-physical and fires the SFO drift
     * compensator spuriously. */
    if (!no_sfo_inference)
        lora_decoder_set_center_freq(dec, channel_hz);

    /* Mix oscillator: shift the channel to DC. */
    double freq_offset_hz = channel_hz - center_hz;
    double mix_inc        = -2.0 * M_PI * freq_offset_hz / samp_rate;
    double mix_phase      = 0.0;

    /* Post-DDC CFO injector. Multiplies output samples by exp(j*2*pi*
     * inject_cfo_hz * n / channel_rate). Used to stress-test the
     * decoder's CFO tracking on a clean synthetic frame: turn the
     * knob from 0 -> +5/+10/+15 kHz and watch when payload_crc_pass
     * collapses. */
    double cfo_inc        = 2.0 * M_PI * inject_cfo_hz / channel_rate;
    double cfo_phase      = 0.0;

    /* FIR state. cutoff = bw/2 keeps the entire chirp passband, with
     * stopband well inside the next-channel boundary. */
    float *taps = NULL;
    float complex *delay = NULL;
    int delay_head = 0;
    if (!skip_ddc) {
        taps = malloc(sizeof(float) * (size_t)n_taps);
        if (!taps) { fclose(f); return 1; }
        n_taps = build_lpf(n_taps, samp_rate, (double)bw_hz * 0.5, taps);
        delay = calloc((size_t)n_taps, sizeof(float complex));
        if (!delay) { free(taps); fclose(f); return 1; }
    }

    /* Read in chunks and stream through DDC -> decim -> decoder.
     * cf32 input bypasses both byte conversion and the DDC entirely
     * when --no-ddc; CFO injection still runs because we want to test
     * the decoder against a synthetic frame at known carrier offsets. */
    const size_t CHUNK = 65536; /* complex samples */
    int8_t *raw_cs8  = NULL;
    float  *raw_cf32 = NULL;
    if (fmt_cf32) raw_cf32 = malloc(sizeof(float) * 2 * CHUNK);
    else          raw_cs8  = malloc(2 * CHUNK);
    float complex *out = malloc(sizeof(float complex) * CHUNK);
    if ((!raw_cs8 && !raw_cf32) || !out) {
        free(taps); free(delay); free(raw_cs8); free(raw_cf32); fclose(f); return 1;
    }
    size_t in_sample_bytes = fmt_cf32 ? (2 * sizeof(float)) : 2;
    uint64_t total_in_samps  = 0;
    uint64_t total_out_samps = 0;
    uint64_t budget = (duration_s > 0.0) ? (uint64_t)(samp_rate * duration_s) : (uint64_t)-1;
    int decim_phase = 0;
    while (total_in_samps < budget) {
        size_t want = CHUNK;
        if (total_in_samps + want > budget) want = (size_t)(budget - total_in_samps);
        void *raw_buf = fmt_cf32 ? (void *)raw_cf32 : (void *)raw_cs8;
        size_t got_bytes = fread(raw_buf, 1, in_sample_bytes * want, f);
        if (got_bytes < in_sample_bytes) break;
        size_t got = got_bytes / in_sample_bytes;
        size_t out_n = 0;
        for (size_t i = 0; i < got; ++i) {
            float ii, qq;
            if (fmt_cf32) {
                ii = raw_cf32[2*i+0];
                qq = raw_cf32[2*i+1];
            } else {
                ii = (float)raw_cs8[2*i+0] / 127.0f;
                qq = (float)raw_cs8[2*i+1] / 127.0f;
            }
            float complex s = ii + I * qq;
            if (skip_ddc) {
                out[out_n++] = s;
            } else {
                /* Mix to DC. */
                float complex mix = (float)cos(mix_phase) + I * (float)sin(mix_phase);
                mix_phase += mix_inc;
                if (mix_phase >  M_PI) mix_phase -= 2.0 * M_PI;
                if (mix_phase < -M_PI) mix_phase += 2.0 * M_PI;
                float complex mixed = s * mix;
                /* FIR delay line. */
                delay[delay_head] = mixed;
                ++decim_phase;
                if (decim_phase >= decim) {
                    decim_phase = 0;
                    /* Compute one output sample. */
                    float complex acc = 0.0f + 0.0f * I;
                    int idx = delay_head;
                    for (int k = 0; k < n_taps; ++k) {
                        acc += delay[idx] * taps[k];
                        idx = (idx == 0) ? (n_taps - 1) : (idx - 1);
                    }
                    out[out_n++] = acc;
                }
                delay_head = (delay_head + 1) % n_taps;
            }
        }
        /* Inject CFO at the post-DDC rate (channel_rate). Done as a
         * second pass over the just-produced out[] so the per-sample
         * phase increment uses channel_rate, not samp_rate. */
        if (inject_cfo_hz != 0.0 && out_n > 0) {
            for (size_t k = 0; k < out_n; ++k) {
                float complex tw = (float complex)(cos(cfo_phase) + I * sin(cfo_phase));
                out[k] = out[k] * tw;
                cfo_phase += cfo_inc;
                if (cfo_phase >  M_PI) cfo_phase -= 2.0 * M_PI;
                if (cfo_phase < -M_PI) cfo_phase += 2.0 * M_PI;
            }
        }
        if (out_n > 0) {
            lora_decoder_feed(dec, out, out_n);
            total_out_samps += out_n;
        }
        total_in_samps += got;
    }
    fprintf(stderr,
        "test_oversample_self: read %llu input samples (%.2f s), fed %llu post-decim samples to decoder\n",
        (unsigned long long)total_in_samps, total_in_samps / samp_rate,
        (unsigned long long)total_out_samps);
    fprintf(stderr, "test_oversample_self: %llu frame(s) delivered.\n",
            (unsigned long long)g_frames);

    lora_demod_stats_dump(stderr);

    lora_decoder_destroy(dec);
    free(raw_cs8); free(raw_cf32); free(out); free(delay); free(taps);
    fclose(f);
    return 0;
}
