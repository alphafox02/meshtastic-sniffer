/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * HackRF native backend for inmarsat-sniffer.
 * Ported from iridium-sniffer's hackrf.c.
 *
 */

#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libhackrf/hackrf.h>

#include "sdr.h"
#include "hackrf.h"

extern double samp_rate;
extern double center_freq;
extern int bias_tee;
extern volatile sig_atomic_t running;

extern int hackrf_lna_gain;
extern int hackrf_vga_gain;
extern int hackrf_amp_enable;

extern void push_samples(sample_buf_t *buf);

void hackrf_backend_list(void)
{
    hackrf_init();
    hackrf_device_list_t *list = hackrf_device_list();
    if (!list || list->devicecount == 0) {
        printf("  (no HackRF devices found)\n");
        if (list) hackrf_device_list_free(list);
        return;
    }
    for (int i = 0; i < list->devicecount; i++) {
        const char *s = list->serial_numbers[i];
        /* trim leading zeros from serial for cleaner display */
        while (*s == '0') s++;
        printf("  hackrf-%-24s HackRF One\n", s);
    }
    hackrf_device_list_free(list);
}

void *hackrf_backend_setup(const char *serial)
{
    int r;
    hackrf_device *dev = NULL;

    hackrf_init();

    if (serial && serial[0]) {
        r = hackrf_open_by_serial(serial, &dev);
    } else {
        r = hackrf_open(&dev);
    }
    if (r != HACKRF_SUCCESS)
        errx(1, "HackRF open failed: %s", hackrf_error_name(r));

    r = hackrf_set_sample_rate(dev, samp_rate);
    if (r != HACKRF_SUCCESS)
        errx(1, "HackRF set_sample_rate: %s", hackrf_error_name(r));

    r = hackrf_set_freq(dev, (uint64_t)center_freq);
    if (r != HACKRF_SUCCESS)
        errx(1, "HackRF set_freq: %s", hackrf_error_name(r));

    r = hackrf_set_lna_gain(dev, hackrf_lna_gain);
    if (r != HACKRF_SUCCESS)
        warnx("HackRF set_lna_gain(%d): %s", hackrf_lna_gain, hackrf_error_name(r));

    r = hackrf_set_vga_gain(dev, hackrf_vga_gain);
    if (r != HACKRF_SUCCESS)
        warnx("HackRF set_vga_gain(%d): %s", hackrf_vga_gain, hackrf_error_name(r));

    if (hackrf_amp_enable) {
        r = hackrf_set_amp_enable(dev, 1);
        if (r != HACKRF_SUCCESS)
            warnx("HackRF set_amp_enable: %s", hackrf_error_name(r));
    }

    if (bias_tee) {
        r = hackrf_set_antenna_enable(dev, 1);
        if (r != HACKRF_SUCCESS)
            warnx("HackRF bias-tee enable: %s", hackrf_error_name(r));
        else
            fprintf(stderr, "HackRF: bias tee enabled\n");
    }

    fprintf(stderr, "HackRF: serial=%s sr=%.0f freq=%.0f lna=%d vga=%d amp=%d\n",
            serial ? serial : "(auto)", samp_rate, center_freq,
            hackrf_lna_gain, hackrf_vga_gain, hackrf_amp_enable);

    return dev;
}

static int hackrf_rx_cb(hackrf_transfer *t)
{
    if (!running) return 0;
    int nbytes = t->valid_length;
    sample_buf_t *s = malloc(sizeof(*s) + nbytes);
    if (!s) return 0;
    s->format = SAMPLE_FMT_INT8;
    s->num = nbytes / 2;  /* 2 bytes per complex sample (int8 I + int8 Q) */
    memcpy(s->samples, t->buffer, nbytes);
    push_samples(s);
    return 0;
}

void *hackrf_stream_thread(void *arg)
{
    hackrf_device *dev = (hackrf_device *)arg;
    int r = hackrf_start_rx(dev, hackrf_rx_cb, NULL);
    if (r != HACKRF_SUCCESS)
        errx(1, "HackRF start_rx: %s", hackrf_error_name(r));

    while (running)
        usleep(100000);

    hackrf_stop_rx(dev);
    hackrf_close(dev);
    hackrf_exit();
    return NULL;
}
