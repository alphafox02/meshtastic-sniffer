/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Airspy R2/Mini native backend for inmarsat-sniffer
 *
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libairspy/airspy.h>

#include "options.h"
#include "airspy.h"
#include "sdr.h"

extern double samp_rate;
extern double center_freq;
extern double soapy_gain_val;
extern int bias_tee;
extern int verbose;
extern volatile sig_atomic_t running;

extern void push_samples(sample_buf_t *buf);

/* Pick nearest supported sample rate >= requested.
 * R2 firmware typically offers {2500000, 10000000}; Mini offers
 * {3000000, 6000000, 10000000}. Opens a device briefly to query. */
double airspy_pick_samplerate(double requested_hz) {
    struct airspy_device *dev = NULL;
    if (airspy_open(&dev) != AIRSPY_SUCCESS || !dev) return 0;

    uint32_t nrates = 0;
    airspy_get_samplerates(dev, &nrates, 0);
    double picked = 0;
    if (nrates > 0 && nrates < 32) {
        uint32_t rates[32] = {0};
        airspy_get_samplerates(dev, rates, nrates);
        /* Find smallest rate >= requested, else largest available. */
        double best = 0;
        for (uint32_t i = 0; i < nrates; i++) {
            if ((double)rates[i] >= requested_hz) {
                if (best == 0 || rates[i] < best) best = rates[i];
            }
        }
        if (best == 0) {
            for (uint32_t i = 0; i < nrates; i++)
                if (rates[i] > best) best = rates[i];
        }
        picked = best;
    }
    airspy_close(dev);
    return picked;
}

void airspy_backend_list(void) {
    uint64_t serials[16];
    int n = airspy_list_devices(serials, 16);
    if (n <= 0) {
        printf("  (no Airspy devices found)\n");
        return;
    }
    for (int i = 0; i < n; i++)
        printf("  airspy  serial=%016" "lX" "\n", (unsigned long)serials[i]);
}

void *airspy_backend_setup(uint64_t serial) {
    struct airspy_device *dev = NULL;
    int r;

    if (serial == 0)
        r = airspy_open(&dev);
    else
        r = airspy_open_sn(&dev, serial);
    if (r != AIRSPY_SUCCESS || !dev)
        errx(1, "Airspy: failed to open device (%s)",
             airspy_error_name((enum airspy_error)r));

    char version[128] = {0};
    airspy_version_string_read(dev, version, sizeof(version));
    fprintf(stderr, "Airspy: opened (fw: %s)\n", version);

    /* Float IQ output — matches what the channelizer expects after
     * the int8 → float conversion other backends do inline. */
    r = airspy_set_sample_type(dev, AIRSPY_SAMPLE_FLOAT32_IQ);
    if (r != AIRSPY_SUCCESS)
        errx(1, "Airspy: set_sample_type failed (%s)", airspy_error_name(r));

    /* Sample rate. If the caller-selected samp_rate isn't exactly
     * supported, pick the nearest supported value >= it and update
     * the global so the rest of the pipeline knows. */
    uint32_t nrates = 0;
    airspy_get_samplerates(dev, &nrates, 0);
    if (nrates == 0 || nrates > 32)
        errx(1, "Airspy: bad samplerate list (%u)", nrates);
    uint32_t rates[32] = {0};
    airspy_get_samplerates(dev, rates, nrates);

    uint32_t target = (uint32_t)samp_rate;
    uint32_t pick = 0;
    for (uint32_t i = 0; i < nrates; i++) {
        if (rates[i] >= target && (pick == 0 || rates[i] < pick))
            pick = rates[i];
    }
    if (pick == 0) {
        for (uint32_t i = 0; i < nrates; i++) if (rates[i] > pick) pick = rates[i];
    }
    if (pick != target) {
        fprintf(stderr, "Airspy: requested %u, using %u (nearest supported)\n",
                target, pick);
        samp_rate = (double)pick;
    }
    r = airspy_set_samplerate(dev, pick);
    if (r != AIRSPY_SUCCESS)
        errx(1, "Airspy: set_samplerate %u failed (%s)", pick, airspy_error_name(r));

    r = airspy_set_freq(dev, (uint32_t)center_freq);
    if (r != AIRSPY_SUCCESS)
        errx(1, "Airspy: set_freq failed (%s)", airspy_error_name(r));

    /* Gain priority: --airspy-gain (native 0..21) wins, then explicit
     * --soapy-gain (mapped from dB), else Airspy's working default of 19.
     * Issue #15: previously the default was unreachable because the
     * global soapy_gain_val starts at 40, so the dB-mapping branch
     * always fired and produced 17 even when nothing was passed. */
    extern int soapy_gain_explicit;
    int lg = 19;
    if (airspy_gain_val >= 0) {
        lg = airspy_gain_val;
    } else if (soapy_gain_explicit) {
        lg = (int)((soapy_gain_val / 49.6) * 21.0 + 0.5);
        if (lg < 0)  lg = 0;
        if (lg > 21) lg = 21;
    }
    r = airspy_set_linearity_gain(dev, (uint8_t)lg);
    if (r != AIRSPY_SUCCESS)
        warnx("Airspy: set_linearity_gain failed (%s)", airspy_error_name(r));
    fprintf(stderr, "Airspy: linearity_gain=%d (0..21)\n", lg);

    if (bias_tee) {
        airspy_set_rf_bias(dev, 1);
        fprintf(stderr, "Airspy: bias tee enabled\n");
    }

    /* Packing halves USB bandwidth at the cost of a tiny CPU hit —
     * always a win for 10 MSPS over USB2. */
    airspy_set_packing(dev, 1);

    fprintf(stderr, "Airspy: tuned to %.3f MHz @ %.3f Msps\n",
            center_freq / 1e6, samp_rate / 1e6);

    return dev;
}

static int airspy_rx_cb(airspy_transfer *t) {
    if (!running || !t || t->sample_count <= 0) return 0;

    int n = t->sample_count;
    sample_buf_t *s = malloc(sizeof(*s) + (size_t)n * sizeof(float) * 2);
    if (!s) return 0;
    s->format = SAMPLE_FMT_FLOAT;
    s->num = (unsigned)n;
    s->hw_timestamp_ns = 0;

    /* Float32 IQ straight-through — Airspy provides analytic IQ
     * already DC-corrected by the firmware, so no DC blocker here. */
    memcpy(s->samples, t->samples, (size_t)n * sizeof(float) * 2);

    push_samples(s);
    return 0;
}

void *airspy_stream_thread(void *arg) {
    struct airspy_device *dev = (struct airspy_device *)arg;
    int r = airspy_start_rx(dev, airspy_rx_cb, NULL);
    if (r != AIRSPY_SUCCESS) {
        warnx("Airspy: start_rx failed (%s)", airspy_error_name(r));
        running = 0;
        return NULL;
    }
    /* Wait until streaming stops (signal handler flips running). */
    while (running && airspy_is_streaming(dev) == AIRSPY_TRUE)
        usleep(100000);
    airspy_stop_rx(dev);
    running = 0;
    return NULL;
}

void airspy_backend_close(void *ctx) {
    struct airspy_device *dev = (struct airspy_device *)ctx;
    if (dev) {
        airspy_stop_rx(dev);
        airspy_close(dev);
    }
}
