/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: samples pushed in by a host application. See ext_src.h.
 */

#include "ext_src.h"
#include "sdr.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern volatile sig_atomic_t running;

static atomic_int g_ready, g_paused;

void *ext_src_thread(void *arg)
{
    (void)arg;
    atomic_store(&g_ready, 1);
    while (running) usleep(100000);
    atomic_store(&g_ready, 0);
    return NULL;
}

int ext_src_push(const int8_t *iq, size_t nbytes)
{
    if (!running || !atomic_load(&g_ready) || atomic_load(&g_paused) || !iq || nbytes < 2)
        return -1;
    nbytes &= ~(size_t)1;
    sample_buf_t *s = malloc(sizeof(*s) + nbytes);
    if (!s) return -1;
    s->format = SAMPLE_FMT_INT8;
    s->num = (unsigned)(nbytes / 2);
    s->hw_timestamp_ns = 0;
    memcpy(s->samples, iq, nbytes);
    push_samples(s);
    return 0;
}

void ext_src_set_paused(int paused)
{
    atomic_store(&g_paused, paused ? 1 : 0);
}

void sniffer_request_stop(void)
{
    running = 0;
}
