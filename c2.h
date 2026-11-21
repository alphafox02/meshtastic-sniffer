/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: command-and-control dispatch.
 *
 * Transport-independent C2 handlers. The HTTP web layer (web.c) calls
 * these from POST /api endpoint handlers; a future ZMQ DEALER c2 path will
 * call them from the same dispatcher. Each handler:
 *
 *   - takes a request body (the entire POST body or DEALER frame payload)
 *   - writes a response into a caller-provided fixed buffer (no malloc)
 *   - returns an HTTP-style status code (200 ok, 400 bad request, ...)
 *
 * Side effects (keyset add, channelizer extra-freq add, cot endpoint
 * change) happen against the global state that main.c owns; nothing
 * here touches transport. The ROADMAP DEALER-C2 work plugs in below.
 */

#ifndef C2_H
#define C2_H

#include <stddef.h>

/* Response buffer carried on the stack. 256 is enough for every reply
 * the current handlers produce; if a future handler needs more, grow
 * here and revisit callers. */
typedef struct {
    int    status;         /* HTTP-style: 200 / 400 / 500 */
    char   body[256];      /* JSON payload, NUL-terminated */
    size_t body_len;
} c2_response_t;

/* Each handler is named after its current /api/<thing> path. The body
 * pointer may be NULL if the request had no body; handlers MUST handle
 * that case and emit a 400. */
void c2_keys_add        (const char *body, c2_response_t *out);
void c2_share_url       (const char *body, c2_response_t *out);
void c2_extra_freq      (const char *body, c2_response_t *out);
void c2_cot_multicast   (const char *body, c2_response_t *out);

/* Name-based dispatch used by transports that carry the command in an
 * envelope (DEALER socket, future RPC). Supported commands map to the
 * c2_* handlers above:
 *   "keys_add" -> c2_keys_add
 *   "share_url" -> c2_share_url
 *   "extra_freq" -> c2_extra_freq
 *   "cot_multicast" -> c2_cot_multicast
 *   "tx_send" -> tx_send (tx.h; same form body as POST /api/tx, and
 *                like it refused with 403 unless the sniffer runs with --tx)
 * Unknown command names produce a 404 response. */
void c2_dispatch(const char *cmd, const char *body, c2_response_t *out);

#endif /* C2_H */
