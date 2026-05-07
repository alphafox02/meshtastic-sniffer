/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * RTL-SDR native backend for meshtastic-sniffer
 *
 */

#include <err.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtl-sdr.h>

#include "sdr.h"
#include "options.h"

extern int rtl_gain_tenths_db;     /* declared in options.h; if <0, AGC. */

extern void push_samples(sample_buf_t *buf);

/* ---- Device listing ---- */

void rtlsdr_backend_list(void) {
    uint32_t count = rtlsdr_get_device_count();
    if (count == 0) {
        printf("  (no RTL-SDR devices found)\n");
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        char manufact[256], product[256], serial[256];
        rtlsdr_get_device_usb_strings(i, manufact, product, serial);
        printf("  rtl-%u    %s %s (serial: %s)\n", i, manufact, product, serial);
    }
}

/* ---- Setup ---- */

void *rtlsdr_backend_setup(int dev_index) {
    rtlsdr_dev_t *dev = NULL;
    int r;

    uint32_t count = rtlsdr_get_device_count();
    if (count == 0)
        errx(1, "No RTL-SDR devices found");

    if (dev_index < 0 || (uint32_t)dev_index >= count)
        errx(1, "RTL-SDR device index %d out of range (0-%u)", dev_index, count - 1);

    fprintf(stderr, "RTL-SDR: opening device %d (%s)\n",
            dev_index, rtlsdr_get_device_name((uint32_t)dev_index));

    r = rtlsdr_open(&dev, (uint32_t)dev_index);
    if (r < 0)
        errx(1, "Failed to open RTL-SDR device %d", dev_index);

    /* Sample rate */
    r = rtlsdr_set_sample_rate(dev, (uint32_t)samp_rate);
    if (r < 0)
        warnx("RTL-SDR: failed to set sample rate %.0f Hz", samp_rate);

    uint32_t actual_rate = rtlsdr_get_sample_rate(dev);
    if (actual_rate != (uint32_t)samp_rate) {
        fprintf(stderr, "RTL-SDR: actual sample rate: %u Hz\n", actual_rate);
        samp_rate = (double)actual_rate;
    }

    /* PPM correction — RTL-SDR tunes its TCXO scaling (rounded to int).
     * Other backends apply the same value as a software channelizer
     * shift in main.c since their APIs don't expose a per-device PPM. */
    extern double ppm_correction;
    if (ppm_correction != 0.0) {
        rtlsdr_set_freq_correction(dev, (int)(ppm_correction + 0.5));
        fprintf(stderr, "RTL-SDR: PPM correction: %.2f\n", ppm_correction);
    }

    /* Center frequency */
    r = rtlsdr_set_center_freq(dev, (uint32_t)center_freq);
    if (r < 0)
        warnx("RTL-SDR: failed to set center freq %.0f Hz", center_freq);

    fprintf(stderr, "RTL-SDR: tuned to %.3f MHz @ %.3f Msps\n",
            center_freq / 1e6, samp_rate / 1e6);

    extern int agc_enabled;
    rtlsdr_set_tuner_gain_mode(dev, agc_enabled ? 0 : 1);
    rtlsdr_set_agc_mode(dev, agc_enabled ? 1 : 0);
    if (agc_enabled)
        fprintf(stderr, "RTL-SDR: AGC enabled\n");

    /* Find nearest supported gain value.
     * Default to max gain (496 = 49.6 dB) for weak satellite signals,
     * matching SDRReceiver's default. Override with --soapy-gain. */
    int num_gains = rtlsdr_get_tuner_gains(dev, NULL);
    if (num_gains > 0) {
        int *gains = malloc((size_t)num_gains * sizeof(int));
        rtlsdr_get_tuner_gains(dev, gains);

        /* Use max gain if user didn't specify */
        double gain_target = soapy_gain_val;
        if (gain_target <= 40.0) gain_target = 49.6;  /* max for R820T/R828D */
        int target = (int)(gain_target * 10.0);  /* tenths of dB */
        int best = gains[0];
        int best_diff = abs(target - gains[0]);
        for (int i = 1; i < num_gains; i++) {
            int diff = abs(target - gains[i]);
            if (diff < best_diff) {
                best = gains[i];
                best_diff = diff;
            }
        }
        free(gains);

        rtlsdr_set_tuner_gain(dev, best);
        fprintf(stderr, "RTL-SDR: gain set to %.1f dB\n", best / 10.0);
    }

    /* Bias tee */
    if (bias_tee) {
        rtlsdr_set_bias_tee(dev, 1);
        fprintf(stderr, "RTL-SDR: bias tee enabled\n");
    }

    /* Reset buffer before streaming */
    rtlsdr_reset_buffer(dev);

    return dev;
}

/* ---- Async streaming callback ---- */

static void rtlsdr_async_cb(unsigned char *buf, uint32_t len, void *ctx) {
    (void)ctx;

    if (!running)
        return;

    /* RTL-SDR gives unsigned 8-bit IQ pairs (center at 128).
     * Convert to float and apply DC bias correction (matching
     * SDRReceiver's correct_dc_bias=1). Without DC removal, the
     * strong DC spike in RTL-SDR data can prevent demod lock. */
    uint32_t num_samples = len / 2;
    sample_buf_t *s = malloc(sizeof(*s) + num_samples * sizeof(float) * 2);
    if (!s)
        return;

    s->format = SAMPLE_FMT_FLOAT;
    s->num = num_samples;
    s->hw_timestamp_ns = 0;

    /* DC blocker: y[n] = x[n] - x[n-1] + alpha*y[n-1] */
    static float dc_re = 0, dc_im = 0;
    static float prev_re = 0, prev_im = 0;
    const float alpha = 0.998f;

    float *out = (float *)s->samples;
    for (uint32_t i = 0; i < num_samples; i++) {
        float re = ((int)buf[i * 2] - 128) * (1.0f / 128.0f);
        float im = ((int)buf[i * 2 + 1] - 128) * (1.0f / 128.0f);
        dc_re = re - prev_re + alpha * dc_re;
        dc_im = im - prev_im + alpha * dc_im;
        prev_re = re;
        prev_im = im;
        out[i * 2] = dc_re;
        out[i * 2 + 1] = dc_im;
    }

    push_samples(s);
}

/* ---- Streaming thread ---- */

void *rtlsdr_stream_thread(void *arg) {
    rtlsdr_dev_t *dev = (rtlsdr_dev_t *)arg;

    /* Use smaller buffers (16384 bytes = 8192 samples ~3.4ms at 2.4MHz)
     * to avoid bursty processing from the default 256KB buffers. */
    rtlsdr_read_async(dev, rtlsdr_async_cb, NULL, 15, 16384);

    running = 0;
    return NULL;
}

/* ---- Cleanup ---- */

void rtlsdr_backend_close(void *ctx) {
    rtlsdr_dev_t *dev = (rtlsdr_dev_t *)ctx;
    if (dev) {
        rtlsdr_cancel_async(dev);
        rtlsdr_close(dev);
    }
}
