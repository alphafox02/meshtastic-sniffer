/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * BladeRF native backend for inmarsat-sniffer.
 * Ported from iridium-sniffer's bladerf.c, simplified for sample_buf_t.
 *
 */

#include <complex.h>
#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libbladeRF.h>

#include "sdr.h"
#include "bladerf.h"

static const unsigned num_transfers = 7;
static unsigned timeouts = 0;

extern volatile sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern int bladerf_gain_val;
extern int bias_tee;
extern int verbose;

extern void push_samples(sample_buf_t *buf);

void bladerf_backend_list(void)
{
    struct bladerf_devinfo *devices = NULL;
    int num = bladerf_get_device_list(&devices);
    if (num <= 0) {
        printf("  (no BladeRF devices found)\n");
        if (num == 0 && devices) bladerf_free_device_list(devices);
        return;
    }
    for (int i = 0; i < num; i++) {
        printf("  bladerf%d                 BladeRF %s (serial %s)\n",
               devices[i].instance, devices[i].product, devices[i].serial);
    }
    bladerf_free_device_list(devices);
}

void *bladerf_backend_setup(int instance)
{
    struct bladerf *dev = NULL;
    char ident[32];
    snprintf(ident, sizeof(ident), "*:instance=%d", instance);

    int status = bladerf_open(&dev, ident);
    if (status != 0) {
        /* fall back to first available */
        status = bladerf_open(&dev, NULL);
        if (status != 0)
            errx(1, "BladeRF open: %s", bladerf_strerror(status));
    }

    status = bladerf_set_bandwidth(dev, BLADERF_CHANNEL_RX(0),
                                    (unsigned)(samp_rate * 0.9), NULL);
    if (status != 0)
        errx(1, "BladeRF set_bandwidth: %s", bladerf_strerror(status));

    status = bladerf_set_frequency(dev, BLADERF_CHANNEL_RX(0),
                                    (uint64_t)center_freq);
    if (status != 0)
        errx(1, "BladeRF set_frequency: %s", bladerf_strerror(status));

    bladerf_set_gain_mode(dev, BLADERF_CHANNEL_RX(0), BLADERF_GAIN_MGC);
    status = bladerf_set_gain(dev, BLADERF_CHANNEL_RX(0), bladerf_gain_val);
    if (status != 0)
        warnx("BladeRF set_gain(%d): %s", bladerf_gain_val,
              bladerf_strerror(status));

    if (bias_tee) {
        status = bladerf_set_bias_tee(dev, BLADERF_CHANNEL_RX(0), true);
        if (status != 0)
            warnx("BladeRF bias-tee: %s", bladerf_strerror(status));
        else
            fprintf(stderr, "BladeRF: bias tee enabled\n");
    }

    fprintf(stderr, "BladeRF: instance=%d sr=%.0f freq=%.0f gain=%d\n",
            instance, samp_rate, center_freq, bladerf_gain_val);

    return dev;
}

static void *bladerf_rx_cb(struct bladerf *dev, struct bladerf_stream *stream,
                            struct bladerf_metadata *meta,
                            void *samples, size_t num_samples, void *user)
{
    (void)dev; (void)stream; (void)meta; (void)user;
    timeouts = 0;
    int16_t *d = (int16_t *)samples;

    sample_buf_t *s = malloc(sizeof(*s) + num_samples * sizeof(float) * 2);
    if (!s) return samples;
    s->format = SAMPLE_FMT_FLOAT;
    s->num = num_samples;
    float *out = (float *)s->samples;
    for (size_t i = 0; i < num_samples * 2; i++)
        out[i] = d[i] * (1.0f / 2048.0f);

    if (running)
        push_samples(s);
    else
        free(s);
    return samples;
}

void *bladerf_stream_thread(void *arg)
{
    struct bladerf *dev = (struct bladerf *)arg;
    struct bladerf_stream *stream;
    struct bladerf_rational_rate rate = {
        .integer = (uint64_t)samp_rate, .num = 0, .den = 1
    };
    void **buffers = NULL;
    const unsigned buf_samples = 16384;

    int status = bladerf_init_stream(&stream, dev, bladerf_rx_cb, &buffers,
                                      num_transfers, BLADERF_FORMAT_SC16_Q11,
                                      buf_samples, num_transfers, NULL);
    if (status != 0)
        errx(1, "BladeRF init_stream: %s", bladerf_strerror(status));

    status = bladerf_set_rational_sample_rate(dev, BLADERF_CHANNEL_RX(0),
                                               &rate, NULL);
    if (status != 0)
        errx(1, "BladeRF set_rational_sample_rate: %s", bladerf_strerror(status));

    unsigned timeout = (unsigned)(1000.0 * buf_samples / samp_rate);
    if (bladerf_set_stream_timeout(dev, BLADERF_MODULE_RX,
                                    timeout * (num_transfers + 2)) != 0)
        errx(1, "BladeRF set_stream_timeout");

    if (bladerf_enable_module(dev, BLADERF_MODULE_RX, true) != 0)
        errx(1, "BladeRF enable_module");

    timeouts = 0;
    while (running) {
        status = bladerf_stream(stream, BLADERF_MODULE_RX);
        if (status < 0) {
            if (status != BLADERF_ERR_TIMEOUT) break;
            if (++timeouts < 5) continue;
            warnx("BladeRF: timed out too many times");
            running = 0;
        }
    }

    bladerf_enable_module(dev, BLADERF_MODULE_RX, false);
    kill(self_pid, SIGINT);
    return NULL;
}
