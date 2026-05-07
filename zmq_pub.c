/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: ZMQ PUB output.
 *
 * One PUB socket bound or connected to --zmq=ENDPOINT (default
 * tcp endpoints, default tcp://(asterisk):7008). One JSON line per send. Uses ZMQ_DONTWAIT so a
 * stalled subscriber drops messages rather than blocking decode.
 *
 */

#include "options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ZMQ

#include <zmq.h>

static void *g_ctx = NULL;
static void *g_sock = NULL;

void zmq_pub_init(void)
{
    if (!opt_zmq_endpoint) return;
    g_ctx = zmq_ctx_new();
    if (!g_ctx) { fprintf(stderr, "zmq: ctx_new failed\n"); return; }
    g_sock = zmq_socket(g_ctx, ZMQ_PUB);
    if (!g_sock) {
        fprintf(stderr, "zmq: socket failed\n");
        zmq_ctx_term(g_ctx); g_ctx = NULL; return;
    }
    int hwm = 1000;
    zmq_setsockopt(g_sock, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    int linger = 0;
    zmq_setsockopt(g_sock, ZMQ_LINGER, &linger, sizeof(linger));

    /* Endpoints with a wildcard host bind; everything else connects. */
    int rc = (strstr(opt_zmq_endpoint, "://*") || strstr(opt_zmq_endpoint, "*:"))
        ? zmq_bind(g_sock, opt_zmq_endpoint)
        : zmq_connect(g_sock, opt_zmq_endpoint);
    if (rc != 0) {
        fprintf(stderr, "zmq: %s %s failed: %s\n",
                rc ? "bind/connect" : "ok", opt_zmq_endpoint, zmq_strerror(zmq_errno()));
        zmq_close(g_sock); g_sock = NULL;
        zmq_ctx_term(g_ctx); g_ctx = NULL;
        return;
    }
    if (verbose) fprintf(stderr, "zmq: PUB %s\n", opt_zmq_endpoint);
}

void zmq_pub_publish(const char *json, size_t len)
{
    if (!g_sock) return;
    zmq_send(g_sock, json, len, ZMQ_DONTWAIT);
}

void zmq_pub_shutdown(void)
{
    if (g_sock) { zmq_close(g_sock); g_sock = NULL; }
    if (g_ctx)  { zmq_ctx_term(g_ctx); g_ctx = NULL; }
}

#else  /* !HAVE_ZMQ */

void zmq_pub_init(void) {}
void zmq_pub_publish(const char *json, size_t len) { (void)json; (void)len; }
void zmq_pub_shutdown(void) {}

#endif
