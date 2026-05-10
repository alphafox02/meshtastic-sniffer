/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * USRP (UHD) native backend for inmarsat-sniffer.
 * Ported from iridium-sniffer's usrp.c, simplified for sample_buf_t.
 *
 */

#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <uhd.h>

#include "options.h"
#include "sdr.h"
#include "usrp.h"

extern volatile sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern int verbose;

extern void push_samples(sample_buf_t *buf);

/* Tiny k=v,k2=v2 parser used on UHD's device discovery string. */
#define KVLEN 32
typedef struct { char key[KVLEN]; char value[KVLEN]; } kv_pair_t;

static kv_pair_t *parse_kv_pairs(char *str, unsigned *pairs_out)
{
    char *cur = str, *end = str + strlen(str);
    unsigned pair = 0;
    char *comma;
    while (cur < end) {
        pair++;
        if ((comma = strchr(cur, ',')) != NULL) cur = comma + 1;
        else break;
    }
    kv_pair_t *ret = calloc(pair, sizeof(*ret));
    pair = 0;
    cur = str;
    while (cur < end) {
        if ((comma = strchr(cur, ',')) != NULL) *comma = 0;
        char *eq = strchr(cur, '=');
        if (!eq) { free(ret); return NULL; }
        *eq = 0;
        strncpy(ret[pair].key, cur, KVLEN - 1);
        strncpy(ret[pair].value, eq + 1, KVLEN - 1);
        pair++;
        if (!comma) break;
        cur = comma + 1;
    }
    *pairs_out = pair;
    return ret;
}

static const char *kv_find(const char *key, const kv_pair_t *p, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (strcmp(p[i].key, key) == 0) return p[i].value;
    return NULL;
}

void usrp_backend_list(void)
{
    uhd_string_vector_handle devices;
    uhd_string_vector_make(&devices);
    uhd_usrp_find("", &devices);
    size_t n = 0;
    uhd_string_vector_size(devices, &n);
    if (n == 0) {
        printf("  (no USRP devices found)\n");
    }
    for (size_t i = 0; i < n; i++) {
        char buf[128];
        uhd_string_vector_at(devices, i, buf, sizeof(buf));
        unsigned pairs = 0;
        kv_pair_t *info = parse_kv_pairs(buf, &pairs);
        if (!info) continue;
        const char *product = kv_find("product", info, pairs);
        const char *serial = kv_find("serial", info, pairs);
        if (product && serial) {
            char id[128];
            snprintf(id, sizeof(id), "usrp-%s-%s", product, serial);
            printf("  %-24s USRP %s\n", id, product);
        }
        free(info);
    }
    uhd_string_vector_free(&devices);
}

/* Parse 'usrp-PRODUCT-SERIAL' → returns pointer to SERIAL portion (static). */
char *usrp_get_serial(const char *name)
{
    static char serial[64];
    if (strncmp(name, "usrp-", 5) != 0) return NULL;
    const char *after = name + 5;
    const char *dash = strchr(after, '-');
    if (!dash) return NULL;
    strncpy(serial, dash + 1, sizeof(serial) - 1);
    serial[sizeof(serial) - 1] = 0;
    return serial;
}

void *usrp_backend_setup(const char *serial)
{
    uhd_usrp_handle usrp;
    uhd_tune_request_t tune_request = {
        .target_freq = center_freq,
        .rf_freq_policy = UHD_TUNE_REQUEST_POLICY_AUTO,
        .dsp_freq_policy = UHD_TUNE_REQUEST_POLICY_AUTO,
    };
    uhd_tune_result_t tune_result;
    char arg[128];

    snprintf(arg, sizeof(arg), "serial=%s,num_recv_frames=1024",
             serial ? serial : "");

    if (uhd_usrp_make(&usrp, arg) != UHD_ERROR_NONE)
        errx(1, "USRP make failed (serial=%s)", serial ? serial : "(any)");

    /* Clock + time source: external/gpsdo for time-disciplined captures
     * (Octoclock, internal GPSDO daughter, GPSDO-disciplined external 10
     * MHz + 1PPS). Internal stays the default. Order matters per UHD:
     * set the clock source first, then time, then sample-rate-dependent
     * config -- changing clock source after rate corrupts the rate set. */
    if (opt_clock_src == CLOCK_SRC_EXTERNAL) {
        if (uhd_usrp_set_clock_source(usrp, "external", 0) != UHD_ERROR_NONE)
            warnx("USRP set_clock_source(external)");
        if (uhd_usrp_set_time_source(usrp, "external", 0) != UHD_ERROR_NONE)
            warnx("USRP set_time_source(external)");
        fprintf(stderr, "USRP: clock+time = external (10 MHz + 1PPS in)\n");
    } else if (opt_clock_src == CLOCK_SRC_GPSDO) {
        if (uhd_usrp_set_clock_source(usrp, "gpsdo", 0) != UHD_ERROR_NONE)
            warnx("USRP set_clock_source(gpsdo) -- requires GPSDO module");
        if (uhd_usrp_set_time_source(usrp, "gpsdo", 0) != UHD_ERROR_NONE)
            warnx("USRP set_time_source(gpsdo)");
        fprintf(stderr, "USRP: clock+time = gpsdo (internal GPSDO module)\n");
    }

    if (uhd_usrp_set_rx_rate(usrp, samp_rate, 0) != UHD_ERROR_NONE)
        errx(1, "USRP set_rx_rate");
    if (uhd_usrp_set_rx_gain(usrp, (double)usrp_gain_val, 0, "") != UHD_ERROR_NONE)
        warnx("USRP set_rx_gain(%d)", usrp_gain_val);
    if (uhd_usrp_set_rx_freq(usrp, &tune_request, 0, &tune_result) != UHD_ERROR_NONE)
        errx(1, "USRP set_rx_freq");

    /* B210 and similar direct-conversion USRPs have a DC spike at the tuned
     * center frequency. Without automatic DC-offset correction the demod
     * constellation collapses to a DC point, variance goes to ~0, and our
     * Eb/No calc hits its 50 dB clamp on every channel while decoding
     * nothing. Also enable automatic I/Q imbalance correction. */
    if (uhd_usrp_set_rx_dc_offset_enabled(usrp, true, 0) != UHD_ERROR_NONE)
        warnx("USRP set_rx_dc_offset_enabled");
    if (uhd_usrp_set_rx_iq_balance_enabled(usrp, true, 0) != UHD_ERROR_NONE)
        warnx("USRP set_rx_iq_balance_enabled");

    fprintf(stderr, "USRP: serial=%s sr=%.0f freq=%.0f gain=%d\n",
            serial ? serial : "(any)", samp_rate, center_freq, usrp_gain_val);

    return usrp;
}

void *usrp_stream_thread(void *arg)
{
    uhd_usrp_handle usrp = (uhd_usrp_handle)arg;
    uhd_rx_streamer_handle rx;
    uhd_rx_metadata_handle md;
    size_t channel = 0, max_samples, rx_samples;
    /* sc16 on the wire preserves the 12-bit ADC; fc32 on the CPU side
     * matches the float path used by other backends. */
    uhd_stream_args_t stream_args = {
        .cpu_format = "fc32",
        .otw_format = "sc16",
        .args = "",
        .channel_list = &channel,
        .n_channels = 1,
    };
    uhd_stream_cmd_t start_cmd = {
        .stream_mode = UHD_STREAM_MODE_START_CONTINUOUS,
        .stream_now = 1,
    };

    uhd_rx_metadata_make(&md);
    uhd_rx_streamer_make(&rx);
    if (uhd_usrp_get_rx_stream(usrp, &stream_args, rx) != UHD_ERROR_NONE)
        errx(1, "USRP get_rx_stream");

    uhd_rx_streamer_max_num_samps(rx, &max_samples);
    uhd_rx_streamer_issue_stream_cmd(rx, &start_cmd);

    while (running) {
        /* fc32 = 2 floats per IQ sample = 8 bytes/sample */
        sample_buf_t *s = malloc(sizeof(*s) + max_samples * sizeof(float) * 2);
        if (!s) break;
        s->format = SAMPLE_FMT_FLOAT;
        void *buf = s->samples;
        uhd_rx_streamer_recv(rx, &buf, max_samples, &md, 3.0, false, &rx_samples);
        uhd_rx_metadata_error_code_t err_code;
        uhd_rx_metadata_error_code(md, &err_code);
        if (err_code != UHD_RX_METADATA_ERROR_CODE_NONE && err_code != 8) {
            free(s);
            warnx("USRP stream error %u", err_code);
            continue;
        }
        s->num = rx_samples;
        if (running) push_samples(s);
        else free(s);
    }

    uhd_stream_cmd_t stop_cmd = { .stream_mode = UHD_STREAM_MODE_STOP_CONTINUOUS };
    uhd_rx_streamer_issue_stream_cmd(rx, &stop_cmd);
    uhd_rx_streamer_free(&rx);
    uhd_rx_metadata_free(&md);
    return NULL;
}
