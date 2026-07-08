/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: command-and-control dispatch.
 *
 * Body parsing + side-effect application for each /api/<endpoint>
 * action, transport-independent. The HTTP web layer in web.c parses
 * an HTTP POST and calls these; a future DEALER socket path will
 * call them with a frame body. Both produce the same JSON response.
 *
 * Helpers that depend on raw HTTP semantics (URL-decode, content-length
 * walk) stay in web.c -- those are coupled to the HTTP request shape.
 * The channel-share protobuf decoder itself is transport-agnostic and
 * lives in share_url.c so CLI startup import and the web/API path use
 * the same parser.
 */

#include "c2.h"
#include "cot.h"
#include "keyset.h"
#include "share_url.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forwards from main.c -- the channel-set is global state owned there. */
extern keyset_t *app_get_keyset(void);
extern int       app_add_runtime_extra_freq(uint64_t f_hz, int bw_hz, int sf, int cr);

static void respond(c2_response_t *out, int status, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out->body, sizeof(out->body), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(out->body)) n = (int)sizeof(out->body) - 1;
    out->body_len = (size_t)n;
    out->status   = status;
}

void c2_keys_add(const char *body, c2_response_t *out)
{
    keyset_t *ks = app_get_keyset();
    if (!body || !ks) {
        respond(out, 400, "{\"error\":\"no body or no keyset\"}");
        return;
    }
    int added = keyset_parse_csv(ks, body);
    respond(out, 200, "{\"added\":%d}", added);
}

void c2_share_url(const char *body, c2_response_t *out)
{
    keyset_t *ks = app_get_keyset();
    if (!body || !ks) {
        respond(out, 400, "{\"error\":\"no body or no keyset\"}");
        return;
    }
    int added = decode_channel_share(ks, body);
    if (added < 0) {
        respond(out, 400, "{\"error\":\"could not parse share URL\"}");
        return;
    }
    respond(out, 200, "{\"added\":%d}", added);
}

void c2_extra_freq(const char *body, c2_response_t *out)
{
    if (!body) {
        respond(out, 400, "{\"error\":\"no body\"}");
        return;
    }
    /* Format: "HZ:bw=BW:sf=SF:cr=CR" -- match the CLI parser. */
    uint64_t f = strtoull(body, NULL, 10);
    int bw = 250000, sf = 11, cr = 5;
    const char *p = body;
    while ((p = strchr(p, ':')) != NULL) {
        ++p;
        if      (!strncmp(p, "bw=", 3)) bw = atoi(p + 3);
        else if (!strncmp(p, "sf=", 3)) sf = atoi(p + 3);
        else if (!strncmp(p, "cr=", 3)) cr = atoi(p + 3);
    }
    int id = (f && bw) ? app_add_runtime_extra_freq(f, bw, sf, cr) : -1;
    if (id < 0) {
        respond(out, 400, "{\"error\":\"add failed\"}");
        return;
    }
    respond(out, 200, "{\"channel_id\":%d}", id);
}

void c2_cot_multicast(const char *body, c2_response_t *out)
{
    if (!body) {
        respond(out, 400, "{\"error\":\"no body\"}");
        return;
    }
    /* Body: "HOST:PORT" or empty to disable. */
    const char *colon = strchr(body, ':');
    if (!colon || !*body) {
        cot_set_endpoint(NULL, 0);
        respond(out, 200, "{\"enabled\":false}");
        return;
    }
    char host[64];
    size_t hl = (size_t)(colon - body);
    if (hl >= sizeof(host)) hl = sizeof(host) - 1;
    memcpy(host, body, hl);
    host[hl] = 0;
    int port = atoi(colon + 1);
    int rc = cot_set_endpoint(host, port);
    if (rc < 0) {
        respond(out, 400, "{\"error\":\"could not bind multicast\"}");
        return;
    }
    respond(out, 200, "{\"enabled\":true,\"host\":\"%s\",\"port\":%d}", host, port);
}

void c2_dispatch(const char *cmd, const char *body, c2_response_t *out)
{
    if (!cmd) {
        respond(out, 400, "{\"error\":\"no cmd\"}");
        return;
    }
    if      (!strcmp(cmd, "keys_add"))      c2_keys_add(body, out);
    else if (!strcmp(cmd, "share_url"))     c2_share_url(body, out);
    else if (!strcmp(cmd, "extra_freq"))    c2_extra_freq(body, out);
    else if (!strcmp(cmd, "cot_multicast")) c2_cot_multicast(body, out);
    else respond(out, 404, "{\"error\":\"unknown cmd\"}");
}
