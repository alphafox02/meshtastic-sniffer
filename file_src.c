/*
 * File-replay backend for meshtastic-sniffer.
 *
 * Reads CI8 / CI16 / CF32 IQ from a file at full speed (no rate
 * pacing -- the channelizer is the bottleneck and we want maximum
 * throughput for offline analysis).
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_src.h"
#include "options.h"
#include "sdr.h"
#include "channelizer.h"

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

extern pid_t self_pid;

static iq_format_t guess_format_from_path(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return FMT_CI8;
    if (!strcasecmp(dot, ".cf32") || !strcasecmp(dot, ".fc32"))
        return FMT_CF32;
    if (!strcasecmp(dot, ".cs16") || !strcasecmp(dot, ".sc16") ||
        !strcasecmp(dot, ".ci16"))
        return FMT_CI16;
    /* .cs8/.sc8/.ci8/.iq -> int8 */
    return FMT_CI8;
}

void *file_src_setup(const char *path)
{
    if (!path) errx(1, "file_src_setup: NULL path");

    /* Auto-detect format if user didn't override. */
    if (iq_format == FMT_CI8)
        iq_format = guess_format_from_path(path);

    FILE *f = fopen(path, "rb");
    if (!f) err(1, "fopen %s", path);

    fprintf(stderr, "file: %s (%s)\n",
            path,
            iq_format == FMT_CF32 ? "cf32" :
            iq_format == FMT_CI16 ? "cs16" : "cs8");
    return f;
}

void *file_src_thread(void *arg)
{
    FILE *f = (FILE *)arg;
    const size_t block = 32768;  /* complex samples per read */

    while (running) {
        sample_buf_t *s = NULL;
        size_t got = 0;

        switch (iq_format) {
        case FMT_CI8:
            s = malloc(sizeof(*s) + block * 2);
            if (!s) break;
            s->format = SAMPLE_FMT_INT8;
            got = fread(s->samples, 2, block, f);
            break;

        case FMT_CI16: {
            /* 4 bytes/sample -> downconvert to int8 by >> 8 */
            s = malloc(sizeof(*s) + block * 2);
            if (!s) break;
            s->format = SAMPLE_FMT_INT8;
            int16_t *tmp = malloc(block * 4);
            if (!tmp) { free(s); s = NULL; break; }
            got = fread(tmp, 4, block, f);
            for (size_t i = 0; i < got * 2; i++)
                s->samples[i] = (int8_t)(tmp[i] >> 8);
            free(tmp);
            break;
        }

        case FMT_CF32:
            s = malloc(sizeof(*s) + block * 8);
            if (!s) break;
            s->format = SAMPLE_FMT_FLOAT;
            got = fread(s->samples, 8, block, f);
            break;
        }

        if (!s || got == 0) {
            free(s);
            break;
        }
        s->num = got;
        s->hw_timestamp_ns = 0;
        push_samples(s);
    }

    fclose(f);
    /* Flush any partial channelizer batch so a short frame's last few
     * symbols actually reach the demod before we tear the process down. */
    extern channelizer_t *g_channelizer;
    if (g_channelizer) channelizer_flush(g_channelizer);
    running = 0;
    if (self_pid) kill(self_pid, SIGINT);
    return NULL;
}
