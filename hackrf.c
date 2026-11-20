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

/* Shared with hackrf_tx_play(): the open device, a lock that serializes
 * TX against shutdown, and a flag that makes the RX callback drop samples
 * while the radio is retuned for transmit. */
static hackrf_device  *g_dev = NULL;
static pthread_mutex_t g_dev_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int    g_rx_streaming = 0;
static volatile int    g_tx_active = 0;

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

    g_dev = dev;
    return dev;
}

static int hackrf_rx_cb(hackrf_transfer *t)
{
    if (!running || g_tx_active) return 0;
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
    g_rx_streaming = 1;

    while (running)
        usleep(100000);

    /* Wait for any in-flight transmit to finish before closing. */
    pthread_mutex_lock(&g_dev_lock);
    g_rx_streaming = 0;
    hackrf_stop_rx(dev);
    hackrf_close(dev);
    g_dev = NULL;
    pthread_mutex_unlock(&g_dev_lock);
    hackrf_exit();
    return NULL;
}

/* ---- Transmit (web send box) ---- */

/* Zero-filled buffers to stream after the last IQ byte so the tail of the
 * frame drains through libhackrf's in-flight USB transfers before stop. */
#define TX_TAIL_BUFFERS 6

typedef struct {
    const int8_t *iq;
    size_t        n;
    size_t        pos;
    int           tail_bufs;
    volatile int  done;
} tx_ctx_t;

static int hackrf_tx_cb(hackrf_transfer *t)
{
    tx_ctx_t *c = (tx_ctx_t *)t->tx_ctx;
    size_t want = (size_t)t->buffer_length;
    size_t left = c->n - c->pos;
    size_t take = left < want ? left : want;
    if (take) memcpy(t->buffer, c->iq + c->pos, take);
    if (take < want) memset(t->buffer + take, 0, want - take);
    c->pos += take;
    t->valid_length = t->buffer_length;
    if (c->pos >= c->n && ++c->tail_bufs >= TX_TAIL_BUFFERS)
        c->done = 1;
    return 0;
}

int hackrf_tx_available(void)
{
    return g_dev != NULL && g_rx_streaming;
}

int hackrf_tx_play(const int8_t *iq, size_t nbytes, uint64_t freq_hz,
                   uint32_t rate_hz, int txvga_db, int amp,
                   char *err, size_t errlen)
{
    if (!iq || nbytes < 2 || (nbytes & 1) || rate_hz == 0) {
        snprintf(err, errlen, "bad IQ buffer");
        return -1;
    }
    if (txvga_db < 0)  txvga_db = 0;
    if (txvga_db > 47) txvga_db = 47;

    pthread_mutex_lock(&g_dev_lock);
    hackrf_device *dev = g_dev;
    if (!dev || !g_rx_streaming || !running) {
        pthread_mutex_unlock(&g_dev_lock);
        snprintf(err, errlen, "HackRF is not streaming");
        return -1;
    }

    int rc = -1, r;
    tx_ctx_t ctx = { .iq = iq, .n = nbytes };
    g_tx_active = 1;
    err[0] = 0;

    r = hackrf_stop_rx(dev);
    if (r != HACKRF_SUCCESS) {
        snprintf(err, errlen, "stop_rx: %s", hackrf_error_name(r));
        goto restore;
    }

#define TX_CHECK(call, what) do { \
        r = (call); \
        if (r != HACKRF_SUCCESS) { \
            snprintf(err, errlen, what ": %s", hackrf_error_name(r)); \
            goto restore; \
        } \
    } while (0)

    TX_CHECK(hackrf_set_sample_rate(dev, (double)rate_hz), "set_sample_rate");
    TX_CHECK(hackrf_set_freq(dev, freq_hz), "set_freq");
    TX_CHECK(hackrf_set_amp_enable(dev, amp ? 1 : 0), "set_amp_enable");
    TX_CHECK(hackrf_set_txvga_gain(dev, (uint32_t)txvga_db), "set_txvga_gain");

    TX_CHECK(hackrf_start_tx(dev, hackrf_tx_cb, &ctx), "start_tx");
#undef TX_CHECK

    fprintf(stderr, "HackRF: TX %.3f ms at %.6f MHz, rate=%u, txvga=%d, amp=%d\n",
            1000.0 * (double)(nbytes / 2) / rate_hz, freq_hz / 1e6, rate_hz,
            txvga_db, amp ? 1 : 0);

    /* Frame duration plus generous slack for USB start-up. */
    long budget_ms = (long)(1000.0 * (double)(nbytes / 2) / rate_hz) + 3000;
    for (long waited = 0; !ctx.done && waited < budget_ms; waited += 10) {
        if (hackrf_is_streaming(dev) != HACKRF_TRUE) break;
        usleep(10000);
    }
    hackrf_stop_tx(dev);
    if (ctx.done) rc = 0;
    else snprintf(err, errlen, "TX did not complete (%zu/%zu bytes sent)", ctx.pos, nbytes);

restore:
    /* Back to the RX configuration from hackrf_backend_setup(). */
    hackrf_set_txvga_gain(dev, 0);
    hackrf_set_amp_enable(dev, hackrf_amp_enable);
    hackrf_set_sample_rate(dev, samp_rate);
    hackrf_set_freq(dev, (uint64_t)center_freq);
    hackrf_set_lna_gain(dev, hackrf_lna_gain);
    hackrf_set_vga_gain(dev, hackrf_vga_gain);
    r = hackrf_start_rx(dev, hackrf_rx_cb, NULL);
    if (r != HACKRF_SUCCESS) {
        g_rx_streaming = 0;
        warnx("HackRF: RX restart after TX failed: %s", hackrf_error_name(r));
        if (!err[0])
            snprintf(err, errlen, "RX restart failed: %s", hackrf_error_name(r));
        rc = -1;
    }
    g_tx_active = 0;
    pthread_mutex_unlock(&g_dev_lock);
    return rc;
}
